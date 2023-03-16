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

func newAzCLI(cfg *config.Config, location string) (*azureCli, error) {
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

	location       string
	subscriptionID string
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

func (a *azureCli) createNetworkSecurityGroup(ctx context.Context, baseName string) (*armnetwork.SecurityGroup, error) {
	parameters := armnetwork.SecurityGroup{
		Location: to.Ptr(a.location),
		Properties: &armnetwork.SecurityGroupPropertiesFormat{
			// TODO(gabriel-samfira): extra_specs
			// example: {
			//		openInboundPorts: [80, 443]
			// }
			SecurityRules: []*armnetwork.SecurityRule{},
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

func (a *azureCli) createVirtualMachine(ctx context.Context, imgDetails imageDetails, vmSize, baseName, networkInterfaceID string) (*armcompute.VirtualMachine, error) {
	parameters := armcompute.VirtualMachine{
		Location: to.Ptr(a.location),
		Identity: &armcompute.VirtualMachineIdentity{
			Type: to.Ptr(armcompute.ResourceIdentityTypeNone),
		},
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				ImageReference: &armcompute.ImageReference{
					Offer:     to.Ptr(imgDetails.Offer),
					Publisher: to.Ptr(imgDetails.Publisher),
					SKU:       to.Ptr(imgDetails.SKU),
					Version:   to.Ptr(imgDetails.Version),
				},
				OSDisk: &armcompute.OSDisk{
					Name:         to.Ptr(baseName),
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
					Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
					ManagedDisk: &armcompute.ManagedDiskParameters{
						// TODO(gabriel-samfira): extra_specs
						StorageAccountType: to.Ptr(armcompute.StorageAccountTypesStandardLRS),
					},
					// TODO(gabriel-samfira): extra_specs
					//DiskSizeGB: to.Ptr[int32](100), // default 127G
				},
			},
			HardwareProfile: &armcompute.HardwareProfile{
				VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(vmSize)),
			},
			OSProfile: &armcompute.OSProfile{
				// garm names may be longer than 15 characters, but that should be fine.
				ComputerName: to.Ptr(baseName),
				// TODO(gabriel-samfira): extra_specs
				AdminUsername: to.Ptr("sample-user"),
				AdminPassword: to.Ptr("Password01!@#"),
				//require ssh key for authentication on linux
				//LinuxConfiguration: &armcompute.LinuxConfiguration{
				//	DisablePasswordAuthentication: to.Ptr(true),
				//	SSH: &armcompute.SSHConfiguration{
				//		PublicKeys: []*armcompute.SSHPublicKey{
				//			{
				//				Path:    to.Ptr(fmt.Sprintf("/home/%s/.ssh/authorized_keys", "sample-user")),
				//				KeyData: to.Ptr(string(sshBytes)),
				//			},
				//		},
				//	},
				//},
			},
			NetworkProfile: &armcompute.NetworkProfile{
				NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
					{
						ID: to.Ptr(networkInterfaceID),
					},
				},
			},
		},
	}

	pollerResponse, err := a.vmCli.BeginCreateOrUpdate(ctx, baseName, baseName, parameters, nil)
	if err != nil {
		return nil, err
	}

	resp, err := pollerResponse.PollUntilDone(ctx, nil)
	if err != nil {
		return nil, err
	}

	return &resp.VirtualMachine, nil
}
