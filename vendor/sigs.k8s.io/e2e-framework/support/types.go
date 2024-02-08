/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package support

import (
	"context"

	"k8s.io/client-go/rest"
	"sigs.k8s.io/e2e-framework/klient"
)

type ClusterOpts func(c E2EClusterProvider)

type E2EClusterProvider interface {
	// WithName is used to configure the cluster Name that should be used while setting up the cluster. Might
	// Not apply for all providers.
	WithName(name string) E2EClusterProvider

	// WithVersion helps you override the default version used while using the cluster provider.
	// This can be useful in providing a mechanism to the end users where they want to test their
	// code against a certain specific version of k8s that is not the default one configured
	// for the provider
	WithVersion(version string) E2EClusterProvider

	// WithPath heps you customize the executable binary that is used to back the cluster provider.
	// This is useful in cases where your binary is present in a non standard location output of the
	// PATH variable and you want to use that instead of framework trying to install one on it's own.
	WithPath(path string) E2EClusterProvider

	// WithOpts provides a way to customize the options that can be used while setting up the
	// cluster using the providers such as kind or kwok or anything else. These helpers can be
	// leveraged to setup arguments or configuration values that can be provided while performing
	// the cluster bring up
	WithOpts(opts ...ClusterOpts) E2EClusterProvider

	// Create Provides an interface to start the cluster creation workflow using the selected provider
	Create(ctx context.Context, args ...string) (string, error)

	// CreateWithConfig is used to provide a mechanism where cluster providers that take an input config
	// file and then setup the cluster accordingly. This can be used to provide input such as kind config
	CreateWithConfig(ctx context.Context, configFile string) (string, error)

	// GetKubeconfig provides a way to extract the kubeconfig file associated with the cluster in question
	// using the cluster provider native way
	GetKubeconfig() string

	// GetKubectlContext is used to extract the kubectl context to be used while performing the operation
	GetKubectlContext() string

	// ExportLogs is used to export the cluster logs via the cluster provider native workflow. This
	// can be used to export logs from the cluster after test failures for example to analyze the test
	// failures better after the fact.
	ExportLogs(ctx context.Context, dest string) error

	// Destroy is used to cleanup a cluster brought up as part of the test workflow
	Destroy(ctx context.Context) error

	// SetDefaults is a handler function invoked after creating an object of type E2EClusterProvider. This method is
	// invoked as the first step after creating an object in order to make sure the default values for required
	// attributes are setup accordingly if any.
	SetDefaults() E2EClusterProvider

	// WaitForControlPlane is a helper function that can be used to indiate the Provider based cluster create workflow
	// that the control plane is fully up and running. This method is invoked after the Create/CreateWithConfig handlers
	// and is expected to return an error if the control plane doesn't stabilize. If the provider being implemented
	// does not have a clear mechanism to identify the Control plane readiness or is not required to wait for the control
	// plane to be ready, such providers can simply add a no-op workflow for this function call.
	// Returning an error message from this handler will stop the workflow of e2e-framework as returning an error from this
	// is considered as  failure to provision a cluster
	WaitForControlPlane(ctx context.Context, client klient.Client) error

	// KubernetesRestConfig is a helper function that provides an instance of rest.Config which can then be used to
	// create your own clients if you chose to do so.
	KubernetesRestConfig() *rest.Config
}

type E2EClusterProviderWithImageLoader interface {
	E2EClusterProvider

	// LoadImage is used to load a set of Docker images to the cluster via the cluster provider native workflow
	// Not every provider will have a mechanism like this/need to do this. So, providers that do not have this support
	// can just provide a no-op implementation to be compliant with the interface
	LoadImage(ctx context.Context, image string) error

	// LoadImageArchive is used to provide a mechanism where a tar.gz archive containing the docker images used
	// by the services running on the cluster can be imported and loaded into the cluster prior to the execution of
	// test if required.
	// Not every provider will have a mechanism like this/need to do this. So, providers that do not have this support
	// can just provide a no-op implementation to be compliant with the interface
	LoadImageArchive(ctx context.Context, archivePath string) error
}
