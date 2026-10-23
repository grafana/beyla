// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cloud // import "go.opentelemetry.io/obi/pkg/cloud"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
)

const defaultAzureRefreshTimeout = 30 * time.Second

// AzureInventoryRefresher maps VM addresses and IDs to their scale-set names.
type AzureInventoryRefresher struct {
	compute        *armcompute.ClientFactory
	network        *armnetwork.InterfacesClient
	subscription   string
	resourceGroup  string
	refreshTimeout time.Duration
}

type azureVM struct {
	uuid       string
	privateIPs []string
}

func NewAzureRefresher(compute *armcompute.ClientFactory, network *armnetwork.InterfacesClient,
	subscription, resourceGroup string,
) *AzureInventoryRefresher {
	return &AzureInventoryRefresher{
		compute:        compute,
		network:        network,
		subscription:   subscription,
		resourceGroup:  resourceGroup,
		refreshTimeout: defaultAzureRefreshTimeout,
	}
}

func (i *AzureInventoryRefresher) Name() string { return "azure" }

// Refresh fills the snapshot after all scale sets have been read successfully.
// One deadline covers group enumeration, VM discovery, and network interface lookups.
func (i *AzureInventoryRefresher) Refresh(ctx context.Context, snapshot *MetadataSnapshot) error {
	ctx, cancel := context.WithTimeout(ctx, i.refreshTimeout)
	defer cancel()
	sets, err := i.listScaleSets(ctx)
	if err != nil {
		return err
	}
	next := MetadataSnapshot{
		ServiceByIP:         map[string]string{},
		ServiceByInstanceID: map[string]string{},
	}
	ipOwners := map[string]string{}
	for _, set := range sets {
		if err := i.refreshScaleSet(ctx, set, &next, ipOwners); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	maps.Copy(snapshot.ServiceByIP, next.ServiceByIP)
	maps.Copy(snapshot.ServiceByInstanceID, next.ServiceByInstanceID)
	return nil
}

// AzureInstanceID scopes a VM UUID to its Azure subscription in the shared inventory.
func AzureInstanceID(subscription, uuid string) string {
	return "azure:" + strings.ToLower(subscription) + ":" + strings.ToLower(uuid)
}

// refreshScaleSet adds a Uniform scale set's running VMs to the candidate snapshot.
// IP ownership spans all scale sets in the refresh so overlapping addresses stay unresolved.
func (i *AzureInventoryRefresher) refreshScaleSet(ctx context.Context, set *armcompute.VirtualMachineScaleSet,
	snapshot *MetadataSnapshot, ipOwners map[string]string,
) error {
	if set.Properties != nil && set.Properties.OrchestrationMode != nil &&
		*set.Properties.OrchestrationMode != armcompute.OrchestrationModeUniform {
		// Uniform discovery also runs in resource groups containing Flexible sets.
		if *set.Properties.OrchestrationMode == armcompute.OrchestrationModeFlexible {
			return nil
		}
		return fmt.Errorf("unsupported Azure scale set orchestration mode %q", *set.Properties.OrchestrationMode)
	}
	vms, err := i.uniformVMs(ctx, *set.Name)
	if err != nil {
		var responseErr *azcore.ResponseError
		if errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound {
			// A scale set can disappear after enumeration.
			return nil
		}
		return err
	}
	for _, vm := range vms {
		if err := i.addVM(snapshot, ipOwners, *set.Name, vm); err != nil {
			return err
		}
	}
	return nil
}

func (i *AzureInventoryRefresher) addVM(snapshot *MetadataSnapshot, ipOwners map[string]string, serviceName string, vm *azureVM) error {
	id := AzureInstanceID(i.subscription, vm.uuid)
	if previous, ok := snapshot.ServiceByInstanceID[id]; ok && previous != serviceName {
		return fmt.Errorf("conflicting Azure VM %q belongs to both %q and %q", id, previous, serviceName)
	}
	snapshot.ServiceByInstanceID[id] = serviceName
	for _, ip := range vm.privateIPs {
		if previous, ok := ipOwners[ip]; ok && previous != id {
			// An empty owner keeps this IP ambiguous for the rest of the refresh.
			ipOwners[ip] = ""
			delete(snapshot.ServiceByIP, ip)
			continue
		}
		ipOwners[ip] = id
		snapshot.ServiceByIP[ip] = serviceName
	}
	return nil
}

func (i *AzureInventoryRefresher) listScaleSets(ctx context.Context) ([]*armcompute.VirtualMachineScaleSet, error) {
	var sets []*armcompute.VirtualMachineScaleSet
	pager := i.compute.NewVirtualMachineScaleSetsClient().NewListPager(i.resourceGroup, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Azure scale sets: %w", err)
		}
		for _, set := range page.Value {
			if set == nil || set.Name == nil || *set.Name == "" || set.ID == nil || *set.ID == "" {
				return nil, errors.New("listed Azure scale set has no name or resource ID")
			}
			sets = append(sets, set)
		}
	}
	return sets, nil
}

func (i *AzureInventoryRefresher) runningUniformVMs(ctx context.Context, setName string) ([]*armcompute.VirtualMachineScaleSetVM, error) {
	var members []*armcompute.VirtualMachineScaleSetVM
	pager := i.compute.NewVirtualMachineScaleSetVMsClient().NewListPager(i.resourceGroup, setName,
		&armcompute.VirtualMachineScaleSetVMsClientListOptions{Expand: new("instanceView")})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Azure scale set %q VMs: %w", setName, err)
		}
		for _, vm := range page.Value {
			if vm == nil || vm.Properties == nil {
				return nil, fmt.Errorf("listed Azure scale set %q contains a VM without properties", setName)
			}
			view := vm.Properties.InstanceView
			if view != nil && azureVMRunning(view.Statuses) {
				members = append(members, vm)
			}
		}
	}
	return members, nil
}

// uniformVMs joins identities from Compute with private addresses from Network
// using ARM resource IDs. Results are returned after both API enumerations complete.
func (i *AzureInventoryRefresher) uniformVMs(ctx context.Context, setName string) ([]*azureVM, error) {
	members, err := i.runningUniformVMs(ctx, setName)
	if err != nil {
		return nil, err
	}
	byResourceID, err := indexUniformVMs(members)
	if err != nil {
		return nil, err
	}
	interfaces, err := i.listUniformNICs(ctx, setName)
	if err != nil {
		return nil, err
	}
	if err := attachUniformIPs(byResourceID, interfaces); err != nil {
		return nil, err
	}
	vms := make([]*azureVM, 0, len(byResourceID))
	for _, vm := range byResourceID {
		vms = append(vms, vm)
	}
	return vms, nil
}

func indexUniformVMs(members []*armcompute.VirtualMachineScaleSetVM) (map[string]*azureVM, error) {
	byResourceID := make(map[string]*azureVM, len(members))
	for _, vm := range members {
		if vm.ID == nil || *vm.ID == "" || vm.Properties.VMID == nil || *vm.Properties.VMID == "" {
			return nil, errors.New("running Azure VM has no resource ID or UUID")
		}
		// ARM resource IDs are case-insensitive across Compute and Network responses.
		byResourceID[strings.ToLower(*vm.ID)] = &azureVM{uuid: *vm.Properties.VMID}
	}
	return byResourceID, nil
}

// listUniformNICs lists the virtual network interfaces (NICs) attached to a scale
// set's VMs. Each interface identifies its VM and contains its private IP addresses.
func (i *AzureInventoryRefresher) listUniformNICs(ctx context.Context, setName string) ([]*armnetwork.Interface, error) {
	var interfaces []*armnetwork.Interface
	pager := i.network.NewListVirtualMachineScaleSetNetworkInterfacesPager(i.resourceGroup, setName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing Azure scale set %q network interfaces: %w", setName, err)
		}
		interfaces = append(interfaces, page.Value...)
	}
	return interfaces, nil
}

func attachUniformIPs(byResourceID map[string]*azureVM, interfaces []*armnetwork.Interface) error {
	for _, networkInterface := range interfaces {
		if networkInterface == nil || networkInterface.Properties == nil {
			return errors.New("listed Azure network interface has no properties")
		}
		owner := networkInterface.Properties.VirtualMachine
		if owner == nil || owner.ID == nil {
			continue
		}
		vm, ok := byResourceID[strings.ToLower(*owner.ID)]
		if !ok {
			continue
		}
		ips, err := azurePrivateIPs(networkInterface.Properties.IPConfigurations)
		if err != nil {
			return err
		}
		vm.privateIPs = append(vm.privateIPs, ips...)
	}
	return nil
}

func azurePrivateIPs(configurations []*armnetwork.InterfaceIPConfiguration) ([]string, error) {
	var ips []string
	for _, configuration := range configurations {
		if configuration == nil || configuration.Properties == nil {
			continue
		}
		ip := configuration.Properties.PrivateIPAddress
		if ip == nil || *ip == "" {
			continue
		}
		address, err := netip.ParseAddr(*ip)
		if err != nil {
			return nil, fmt.Errorf("invalid Azure private IP %q: %w", *ip, err)
		}
		ips = append(ips, address.Unmap().String())
	}
	return ips, nil
}

func azureVMRunning(statuses []*armcompute.InstanceViewStatus) bool {
	for _, status := range statuses {
		if status != nil && status.Code != nil && *status.Code == "PowerState/running" {
			return true
		}
	}
	return false
}
