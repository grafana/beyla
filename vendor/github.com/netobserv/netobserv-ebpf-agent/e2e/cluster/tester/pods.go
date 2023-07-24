package tester

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
)

// Pods enables some basic operations in cluster pods (e.g. searching, executing commands...)
type Pods struct {
	restConfig *rest.Config
	client     *kubernetes.Clientset
}

func NewPods(cfg *envconf.Config) (*Pods, error) {
	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return nil, err
	}
	return &Pods{
		restConfig: cfg.Client().RESTConfig(),
		client:     kclient,
	}, nil
}

func (p *Pods) MACAddress(
	ctx context.Context, namespace, name, iface string,
) (net.HardwareAddr, error) {
	mac, errStr, err := p.Execute(ctx, namespace, name, "cat", "/sys/class/net/"+iface+"/address")
	if err != nil {
		return nil, fmt.Errorf("executing command: %w", err)
	}
	if errStr != "" {
		return nil, fmt.Errorf("unexpected stderr: %s", errStr)
	}
	hwaddr, err := net.ParseMAC(strings.Trim(mac, " \n\r"))
	if err != nil {
		return nil, fmt.Errorf("can't parse address %q: %w", mac, err)
	}
	return hwaddr, nil
}

func (p *Pods) Execute(ctx context.Context, namespace, name string, command ...string) (string, string, error) {
	pod, err := p.client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", "", fmt.Errorf("getting pod: %w", err)
	}
	request := p.client.CoreV1().RESTClient().Post().Namespace(pod.Namespace).
		Resource("pods").Name(pod.Name).
		SubResource("exec").VersionedParams(&v1.PodExecOptions{
		Command: command,
		Stdin:   false,
		Stdout:  true,
		Stderr:  true,
		TTY:     true,
	}, scheme.ParameterCodec)
	buf := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	exec, err := remotecommand.NewSPDYExecutor(p.restConfig, "POST", request.URL())
	if err != nil {
		return "", "", fmt.Errorf("instantiating executor: %w", err)
	}
	if err := exec.Stream(remotecommand.StreamOptions{
		Stdout: buf,
		Stderr: errBuf,
	}); err != nil {
		return "", "", fmt.Errorf("executing command: %w", err)
	}
	return buf.String(), errBuf.String(), nil
}
