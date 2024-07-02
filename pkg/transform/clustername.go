// Few lines of code in this file are taken from
// https://github.com/DataDog/datadog-agent,
// published under Apache License 2.0

package transform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

const (
	gcpMetadataURL   = "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-name"
	azureMetadataURL = "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2017-08-01&format=text"

	ec2MetadataURL         = "http://169.254.169.254/latest/meta-data"
	ec2SecurityCredsURL    = ec2MetadataURL + "/iam/security-credentials/"
	ec2InstanceIdentityURL = "http://169.254.169.254/latest/dynamic/instance-identity/document/"
)

var (
	gcpMetadataHeaders   = map[string]string{"Metadata-Flavor": "Google"}
	azureMetadataHeaders = map[string]string{"Metadata": "true"}
)

var metadataClient = http.Client{Timeout: time.Second}

type clusterNameFetcher func(context.Context) (string, error)

// fetchClusterName tries to automatically guess the cluster name from three major
// cloud providers: EC2, GCP, Azure.
// TODO: consider other providers (Alibaba, Oracle, etc...)
func fetchClusterName(ctx context.Context) string {
	log := klog().With("func", "fetchClusterName")
	var clusterNameFetchers = map[string]clusterNameFetcher{
		"EC2":   ec2ClusterNameFetcher,
		"GCP":   gcpClusterNameFetcher,
		"Azure": azureClusterNameFetcher,
	}
	for provider, fetch := range clusterNameFetchers {
		log := log.With("provider", provider)
		log.Debug("trying to retrieve cluster name")
		if name, err := fetch(ctx); err != nil {
			log.Debug("didn't get cluster name", "error", err)
		} else if name != "" {
			log.Debug("successfully got cluster name", "name", name)
			return name
		}
	}
	return ""
}

func httpGet(ctx context.Context, url string, headers map[string]string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("creating HTTP request for %s: %w", url, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := metadataClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("invoking GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s unexpected response: %d %s",
			url, resp.StatusCode, resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}
	return string(bytes.TrimSpace(body)), nil
}

func gcpClusterNameFetcher(ctx context.Context) (string, error) {
	return httpGet(ctx, gcpMetadataURL, gcpMetadataHeaders)
}

func azureClusterNameFetcher(ctx context.Context) (string, error) {
	all, err := httpGet(ctx, azureMetadataURL, azureMetadataHeaders)
	if err != nil {
		return "", err
	}

	// It expects the resource group name to have the format (MC|mc)_resource-group_cluster-name_zone
	splitAll := strings.Split(all, "_")
	if len(splitAll) < 4 || strings.ToLower(splitAll[0]) != "mc" {
		return "", fmt.Errorf("cannot parse the clustername from resource group name: %s", all)
	}

	return splitAll[len(splitAll)-2], nil
}

type ec2Identity struct {
	Region     string
	InstanceID string
	AccountID  string
}

func getInstanceIdentity(ctx context.Context) (*ec2Identity, error) {
	instanceIdentity := &ec2Identity{}

	res, err := httpGet(ctx, ec2InstanceIdentityURL, nil)
	if err != nil {
		return instanceIdentity, fmt.Errorf("unable to fetch EC2 API to get identity: %w", err)
	}

	err = json.Unmarshal([]byte(res), &instanceIdentity)
	if err != nil {
		return instanceIdentity, fmt.Errorf("unable to unmarshall json, %w", err)
	}

	return instanceIdentity, nil
}

type ec2SecurityCred struct {
	AccessKeyID     string
	SecretAccessKey string
	Token           string
}

func getSecurityCreds(ctx context.Context) (*ec2SecurityCred, error) {
	iamParams := &ec2SecurityCred{}

	iamRole, err := getIAMRole(ctx)
	if err != nil {
		return iamParams, err
	}

	res, err := httpGet(ctx, ec2SecurityCredsURL+iamRole, nil)
	if err != nil {
		return iamParams, fmt.Errorf("unable to fetch EC2 API to get iam role: %w", err)
	}

	err = json.Unmarshal([]byte(res), &iamParams)
	if err != nil {
		return iamParams, fmt.Errorf("unable to unmarshall json, %w", err)
	}
	return iamParams, nil
}

func getIAMRole(ctx context.Context) (string, error) {
	res, err := httpGet(ctx, ec2SecurityCredsURL, nil)
	if err != nil {
		return "", fmt.Errorf("unable to fetch EC2 API to get security credentials: %w", err)
	}

	return res, nil
}

func ec2ClusterNameFetcher(ctx context.Context) (string, error) {
	instanceIdentity, err := getInstanceIdentity(ctx)
	if err != nil {
		return "", err
	}

	secCreds, err := getSecurityCreds(ctx)
	if err != nil {
		return "", err
	}
	awsCreds := credentials.NewStaticCredentialsProvider(secCreds.AccessKeyID, secCreds.SecretAccessKey, secCreds.Token)

	connection := ec2.New(ec2.Options{
		Region:      instanceIdentity.Region,
		Credentials: awsCreds,
	})

	ec2Tags, err := connection.DescribeTags(ctx,
		&ec2.DescribeTagsInput{
			Filters: []types.Filter{{
				Name: aws.String("resource-id"),
				Values: []string{
					instanceIdentity.InstanceID,
				},
			}},
		},
	)
	if err != nil {
		return "", fmt.Errorf("retrieving EC2 tags: %w", err)
	}

	// tagsStr is a newline-separated list of strings containing tag keys
	for _, tag := range ec2Tags.Tags {
		if tag.Key == nil {
			continue
		}
		// tag key format: kubernetes.io/cluster/clustername"
		if strings.HasPrefix(*tag.Key, "kubernetes.io/cluster/") {
			return strings.Split(*tag.Key, "/")[2], nil
		}
	}
	return "", errors.New("did not find any kubernetes.io/cluster/... tag")
}
