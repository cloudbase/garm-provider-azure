package client

import (
	"context"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"

	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-azure/internal/spec"
	"github.com/cloudbase/garm-provider-azure/internal/util"
)

func NewAzCLI(cfg *config.Config) (*AzureCli, error) {
	creds, err := cfg.Credentials.GetCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	opts := arm.ClientOptions{
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
	azCli := &AzureCli{
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

type AzureCli struct {
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

func (a *AzureCli) CreateResourceGroup(ctx context.Context, name string, tags map[string]*string) (*armresources.ResourceGroup, error) {
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

func (a *AzureCli) CreateVirtualNetwork(ctx context.Context, baseName, spaceCIDR string) (*armnetwork.VirtualNetwork, error) {
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

func (a *AzureCli) CreateSubnet(ctx context.Context, baseName, subnetCIDR string) (*armnetwork.Subnet, error) {
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

func (a *AzureCli) CreateNetworkSecurityGroup(ctx context.Context, baseName string, spec *spec.RunnerSpec) (*armnetwork.SecurityGroup, error) {
	if spec == nil {
		return nil, fmt.Errorf("invalid nil runner spec")
	}

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

func (a *AzureCli) CreateNetWorkInterface(ctx context.Context, baseName, subnetID, networkSecurityGroupID, publicIPID string) (*armnetwork.Interface, error) {
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

func (a *AzureCli) CreatePublicIP(ctx context.Context, baseName string) (*armnetwork.PublicIPAddress, error) {
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

func (a *AzureCli) CreateVirtualMachine(ctx context.Context, spec *spec.RunnerSpec, networkInterfaceID string, tags map[string]*string) error {
	if spec == nil {
		return fmt.Errorf("invalid nil runner spec")
	}
	properties, err := spec.GetNewVMProperties(networkInterfaceID)
	if err != nil {
		return fmt.Errorf("failed to get new VM properties: %w", err)
	}
	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(a.location),
		Tags:     tags,
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: properties,
	}

	_, err = a.vmCli.BeginCreateOrUpdate(ctx, spec.BootstrapParams.Name, spec.BootstrapParams.Name, parameters, nil)
	if err != nil {
		return fmt.Errorf("failed to create VM: %w", err)
	}

	extName := "CustomScriptExtension"
	computeExtension, err := spec.GetVMExtension(a.location, extName)
	if err != nil {
		return fmt.Errorf("failed to get vm extension: %w", err)
	}

	if computeExtension != nil {
		_, err = a.extCli.BeginCreateOrUpdate(ctx, spec.BootstrapParams.Name, spec.BootstrapParams.Name, extName, *computeExtension, nil)
		if err != nil {
			return fmt.Errorf("failed to create vm extension: %w", err)
		}
	}

	return nil
}

func (a *AzureCli) DeleteResourceGroup(ctx context.Context, resourceGroup string, forceDelete bool) error {
	opts := &armresources.ResourceGroupsClientBeginDeleteOptions{}
	if forceDelete {
		opts.ForceDeletionTypes = to.Ptr("forceDeletionTypes=Microsoft.Compute/virtualMachines")
	}

	pollerResponse, err := a.rgCli.BeginDelete(ctx, resourceGroup, opts)
	if err != nil {
		asRespCode, ok := err.(*azcore.ResponseError)
		if ok {
			if asRespCode.StatusCode == http.StatusNotFound {
				return nil
			}
			// We may not have a VM created yet, so force delete will fail. Retry without force delete.
			if asRespCode.ErrorCode == "UnsupportedForceDeletionResourceTypeInQueryString" {
				return a.DeleteResourceGroup(ctx, resourceGroup, false)
			}
		}
		return fmt.Errorf("failed to delete resource group: %w", err)
	}

	_, err = pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to delete resource group: %w", err)
	}

	return nil
}

func (a *AzureCli) GetInstance(ctx context.Context, rgName, vmName string) (armcompute.VirtualMachine, error) {
	opts := &armcompute.VirtualMachinesClientGetOptions{
		Expand: to.Ptr(armcompute.InstanceViewTypesInstanceView),
	}
	vm, err := a.vmCli.Get(ctx, rgName, rgName, opts)
	if err != nil {
		return armcompute.VirtualMachine{}, fmt.Errorf("failed to get VM: %w", err)
	}
	return vm.VirtualMachine, nil
}

func (a *AzureCli) DealocateVM(ctx context.Context, rgName, vmName string) error {
	poller, err := a.vmCli.BeginDeallocate(ctx, rgName, vmName, nil)
	if err != nil {
		return fmt.Errorf("failed to dealocate VM: %w", err)
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to dealocate vm: %w", err)
	}
	return nil
}

func (a *AzureCli) StartVM(ctx context.Context, vmName string) error {
	poller, err := a.vmCli.BeginStart(ctx, vmName, vmName, nil)
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	if _, err := poller.PollUntilDone(ctx, nil); err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	return nil
}

func (a *AzureCli) ListVirtualMachines(ctx context.Context, poolID string) ([]*armcompute.VirtualMachine, error) {
	options := &armcompute.VirtualMachinesClientListAllOptions{}
	var resp []*armcompute.VirtualMachine
	pager := a.vmCli.NewListAllPager(options)
	for pager.More() {
		nextResult, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list virtual machines: %w", err)
		}
		if nextResult.VirtualMachineListResult.Value != nil {
			for _, vm := range nextResult.VirtualMachineListResult.Value {
				// Sadly, there is no server side filter by tags on this resource.
				if vm.Tags == nil {
					continue
				}
				tag, ok := vm.Tags[util.PoolIDTagName]
				if !ok || *tag != poolID {
					continue
				}
				resp = append(resp, vm)
			}
		}
	}
	return resp, nil
}
