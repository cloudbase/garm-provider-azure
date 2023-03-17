package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/cloudbase/garm-provider-azure/config"
)

func newAzCLI(cfg *config.Config) (*azureCli, error) {
	creds, err := cfg.GetCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	opts := policy.ClientOptions{
		ClientOptions: cfg.Credentials.ClientOptions,
	}
	resourceGroupClient, err := armresources.NewResourceGroupsClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}
	netCli, err := armnetwork.NewVirtualNetworksClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	subnetClient, err := armnetwork.NewSubnetsClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	nsgClient, err := armnetwork.NewSecurityGroupsClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	nicClient, err := armnetwork.NewInterfacesClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	vmClient, err := armcompute.NewVirtualMachinesClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	publicIPcli, err := armnetwork.NewPublicIPAddressesClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}

	extClient, err := armcompute.NewVirtualMachineExtensionsClient(cfg.Credentials.SubscriptionID, creds, &opts)
	if err != nil {
		return nil, err
	}
	azCli := &azureCli{
		cfg:       cfg,
		cred:      creds,
		rgCli:     resourceGroupClient,
		netCli:    netCli,
		subnetCli: subnetClient,
		nsgCli:    nsgClient,
		nicCli:    nicClient,
		vmCli:     vmClient,
		pubIPCli:  publicIPcli,
		extCli:    extClient,
		location:  cfg.Location,
	}
	return azCli, nil
}

type azureCli struct {
	cfg  *config.Config
	cred azcore.TokenCredential

	rgCli     *armresources.ResourceGroupsClient
	netCli    *armnetwork.VirtualNetworksClient
	subnetCli *armnetwork.SubnetsClient
	nsgCli    *armnetwork.SecurityGroupsClient
	nicCli    *armnetwork.InterfacesClient
	vmCli     *armcompute.VirtualMachinesClient
	pubIPCli  *armnetwork.PublicIPAddressesClient
	extCli    *armcompute.VirtualMachineExtensionsClient

	location string
}

func (a *azureCli) createResourceGroup(ctx context.Context, name string, tags map[string]*string) (*armresources.ResourceGroup, error) {
	parameters := armresources.ResourceGroup{
		Location: to.Ptr(a.location),
		Tags:     tags,
	}

	resp, err := a.rgCli.CreateOrUpdate(ctx, name, parameters, nil)
	if err != nil {
		return nil, err
	}

	return &resp.ResourceGroup, nil
}

func (a *azureCli) createVirtualNetwork(ctx context.Context, baseName, spaceCIDR string) (*armnetwork.VirtualNetwork, error) {
	parameters := armnetwork.VirtualNetwork{
		Location: to.Ptr(a.location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{
					to.Ptr(spaceCIDR),
				},
			},
		},
	}

	pollerResponse, err := a.netCli.BeginCreateOrUpdate(ctx, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualNetwork, nil
}

func (a *azureCli) createSubnet(ctx context.Context, baseName, subnetCIDR string) (*armnetwork.Subnet, error) {
	parameters := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: to.Ptr(subnetCIDR),
		},
	}

	pollerResponse, err := a.subnetCli.BeginCreateOrUpdate(ctx, baseName, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Subnet, nil
}

func (a *azureCli) createNetworkSecurityGroup(ctx context.Context, baseName string, spec runnerSpec) (*armnetwork.SecurityGroup, error) {
	rules := spec.SecurityRules()
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(a.location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			SecurityRules: rules,
		},
	}

	pollerResponse, err := a.nsgCli.BeginCreateOrUpdate(ctx, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.SecurityGroup, nil
}

func (a *azureCli) createNetWorkInterface(ctx context.Context, baseName, subnetID, networkSecurityGroupID, publicIPID string) (*armnetwork.Interface, error) {
	interfaceIPConfig := &armnetwork.InterfaceIPConfigurationPropertiesFormat{
		PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
		Subnet: &armnetwork.Subnet{
			ID: to.Ptr(subnetID),
		},
	}

	if publicIPID != "" {
		interfaceIPConfig.PublicIPAddress = &armnetwork.PublicIPAddress{
			ID: to.Ptr(publicIPID),
		}
	}

	parameters := armnetwork.Interface{
		Location: to.Ptr(a.location),
		Properties: &armnetwork.InterfacePropertiesFormat{
			IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
				{
					Name:       to.Ptr("ipConfig"),
					Properties: interfaceIPConfig,
				},
			},
			NetworkSecurityGroup: &armnetwork.SecurityGroup{
				ID: to.Ptr(networkSecurityGroupID),
			},
		},
	}

	pollerResponse, err := a.nicCli.BeginCreateOrUpdate(ctx, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.Interface, err
}

func (a *azureCli) createPublicIP(ctx context.Context, baseName string) (*armnetwork.PublicIPAddress, error) {
	parameters := armnetwork.PublicIPAddress{
		Location: to.Ptr(a.location),
		Properties: &armnetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
		},
	}

	pollerResponse, err := a.pubIPCli.BeginCreateOrUpdate(ctx, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}
	return &resp.PublicIPAddress, err
}

func (a *azureCli) createVirtualMachine(ctx context.Context, spec runnerSpec, networkInterfaceID string, tags map[string]*string) (*armcompute.VirtualMachine, error) {
	properties, err := spec.GetNewVMProperties(networkInterfaceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get new VM properties: %w", err)
	}
	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(a.location),
		Tags:     tags,
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: properties,
	}

	pollerResponse, err := a.vmCli.BeginCreateOrUpdate(ctx, spec.BootstrapParams.Name, spec.BootstrapParams.Name, parameters, nil)
	if err != nil {
		return nil, err
	}

	computeExtension, err := spec.GetVMExtension(a.location)
	if err != nil {
		return nil, fmt.Errorf("failed to get vm extension: %w", err)
	}

	if computeExtension != nil {
		_, err = a.extCli.BeginCreateOrUpdate(ctx, spec.BootstrapParams.Name, spec.BootstrapParams.Name, "CustomScriptExtension", *computeExtension, nil)
		if err != nil {
			return nil, err
		}
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualMachine, nil
}

func (a *azureCli) deleteResourceGroup(ctx context.Context, resourceGroup string) error {
	opts := &armresources.ResourceGroupsClientBeginDeleteOptions{
		ForceDeletionTypes: to.Ptr("forceDeletionTypes=Microsoft.Compute/virtualMachines,Microsoft.Compute/virtualMachineScaleSets"),
	}
	pollerResponse, err := a.rgCli.BeginDelete(ctx, resourceGroup, opts)
	if err != nil {
		return fmt.Errorf("failed to delete resource group: %w", err)
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to delete resource group: %w", err)
	}

	return nil
}

func (a *azureCli) getInstance(ctx context.Context, rgName, vmName string) (armcompute.VirtualMachine, error) {
	opts := &armcompute.VirtualMachinesClientGetOptions{
		Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView),
	}
	vm, err := a.vmCli.Get(ctx, rgName, rgName, opts)
	if err != nil {
		return armcompute.VirtualMachine{}, fmt.Errorf("failed to get VM: %w", err)
	}
	return vm.VirtualMachine, nil
}

func (a *azureCli) listResourceGroups(ctx context.Context, poolID string) ([]*armresources.ResourceGroup, error) {
	// $filter=tagName eq 'tag1' and tagValue eq 'Value1'
	filter := fmt.Sprintf("$filter=tagName eq '%s' and tagValue eq '%s'", poolIDTagName, poolID)
	opts := &armresources.ResourceGroupsClientListOptions{
		Filter: to.Ptr(filter),
	}
	pager := a.rgCli.NewListPager(opts)
	var resourceGroups []*armresources.ResourceGroup
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list resource groups: %w", err)
		}
		if nextResult.ResourceGroupListResult.Value != nil {
			resourceGroups = append(resourceGroups, nextResult.ResourceGroupListResult.Value...)
		}
	}
	return resourceGroups, nil
}

func (a *azureCli) listVirtualMachines(ctx context.Context, poolID string) ([]*armcompute.VirtualMachine, error) {
	filter := fmt.Sprintf("[?tags.%s == '%s']", poolIDTagName, poolID)
	options := &armcompute.VirtualMachinesClientListAllOptions{
		Filter: to.Ptr(filter),
	}
	var resp []*armcompute.VirtualMachine
	pager := a.vmCli.NewListAllPager(options)
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual machines: %w", err)
		}
		if nextResult.VirtualMachineListResult.Value != nil {
			resp = append(resp, nextResult.VirtualMachineListResult.Value...)
		}
	}
	return resp, nil
}
