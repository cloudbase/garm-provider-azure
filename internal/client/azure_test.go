// Copyright 2023 Cloudbase Solutions SRL
//
//    Licensed under the Apache License, Version 2.0 (the "License"); you may
//    not use this file except in compliance with the License. You may obtain
//    a copy of the License at
//
//         http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//    License for the specific language governing permissions and limitations
//    under the License.

package client

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	armcomputefake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5/fake"
	armnetwork "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	armnetworkfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	armresourcesfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/fake"
	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-azure/internal/spec"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
)

// There are fake clients called for example VirtualNetworkServer
// instead of VirtualNetworkClient

func TestCreateResourceGroup(t *testing.T) {
	ctx := context.Background()
	name := "test"
	location := "eastus"
	tags := map[string]*string{"key": to.Ptr("value")}
	myResouceGroupServer := armresourcesfake.ResourceGroupsServer{}
	myResouceGroupServer.CreateOrUpdate = func(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (resp azfake.Responder[armresources.ResourceGroupsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetResponse(200, armresources.ResourceGroupsClientCreateOrUpdateResponse{
			ResourceGroup: armresources.ResourceGroup{
				ID:       to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test"),
				Name:     to.Ptr(name),
				Location: to.Ptr(location),
				Tags:     tags,
			},
		}, nil)

		return resp, errResp
	}
	client, err := armresources.NewResourceGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armresourcesfake.NewResourceGroupsServerTransport(&myResouceGroupServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		rgCli: client,
	}

	resp, err := a.CreateResourceGroup(ctx, name, tags)
	assert.NoError(t, err)
	assert.Equal(t, name, *resp.Name)
	assert.Equal(t, location, *resp.Location)
	assert.Equal(t, tags, resp.Tags)
}

func TestCreateVirtualNetwork(t *testing.T) {
	ctx := context.Background()
	name := "test"
	location := "eastus"
	spaceCIDR := "10.10.0.0/16"
	myVirtualNetworkServer := armnetworkfake.VirtualNetworksServer{}
	myVirtualNetworkServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, parameters armnetwork.VirtualNetwork, options *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armnetwork.VirtualNetworksClientCreateOrUpdateResponse{
			VirtualNetwork: armnetwork.VirtualNetwork{
				ID:       to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test"),
				Name:     to.Ptr(name),
				Location: to.Ptr(location),
				Properties: &armnetwork.VirtualNetworkPropertiesFormat{
					AddressSpace: &armnetwork.AddressSpace{
						AddressPrefixes: []*string{
							to.Ptr(spaceCIDR),
						},
					},
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armnetwork.NewVirtualNetworksClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewVirtualNetworksServerTransport(&myVirtualNetworkServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		netCli: client,
	}

	resp, err := a.CreateVirtualNetwork(ctx, name, spaceCIDR)
	assert.NoError(t, err)
	assert.Equal(t, name, *resp.Name)
	assert.Equal(t, location, *resp.Location)
	assert.Equal(t, spaceCIDR, *resp.Properties.AddressSpace.AddressPrefixes[0])
}

func TestCreateSubnet(t *testing.T) {
	ctx := context.Background()
	baseName := "test"
	spaceCIDR := "10.10.0.0/24"
	mySubnetServer := armnetworkfake.SubnetsServer{}
	mySubnetServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, subnetParameters armnetwork.Subnet, options *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.SubnetsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armnetwork.SubnetsClientCreateOrUpdateResponse{
			Subnet: armnetwork.Subnet{
				ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"),
				Name: to.Ptr(baseName),
				Properties: &armnetwork.SubnetPropertiesFormat{
					AddressPrefix: to.Ptr(spaceCIDR),
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armnetwork.NewSubnetsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewSubnetsServerTransport(&mySubnetServer),
		},
	})

	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		subnetCli: client,
	}

	resp, err := a.CreateSubnet(ctx, baseName, spaceCIDR)
	assert.NoError(t, err)
	assert.Equal(t, baseName, *resp.Name)
	assert.Equal(t, spaceCIDR, *resp.Properties.AddressPrefix)
}

func TestCreateNetworkSecurityGroup(t *testing.T) {
	ctx := context.Background()
	baseName := "test"
	mySecurityGroupServer := armnetworkfake.SecurityGroupsServer{}
	mySecurityGroupServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, networkSecurityGroupName string, parameters armnetwork.SecurityGroup, options *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armnetwork.SecurityGroupsClientCreateOrUpdateResponse{
			SecurityGroup: armnetwork.SecurityGroup{
				ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/nsg-test"),
				Name: to.Ptr(baseName),
				Properties: &armnetwork.SecurityGroupPropertiesFormat{
					SecurityRules: []*armnetwork.SecurityRule{},
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armnetwork.NewSecurityGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewSecurityGroupsServerTransport(&mySecurityGroupServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		nsgCli: client,
	}

	tests := []struct {
		name      string
		spec      *spec.RunnerSpec
		errString string
	}{
		{
			name:      "invalid spec",
			spec:      nil,
			errString: "invalid nil runner spec",
		},
		{
			name: "valid spec",
			spec: &spec.RunnerSpec{
				VMSize:             "Standard_DS2_v2",
				AllocatePublicIP:   true,
				AdminUsername:      "admin",
				StorageAccountType: "Standard_LRS",
				DiskSizeGB:         128,
				OpenInboundPorts: map[armnetwork.SecurityRuleProtocol][]int{
					armnetwork.SecurityRuleProtocolTCP: {22, 80},
					armnetwork.SecurityRuleProtocolUDP: {53},
				},
				BootstrapParams: params.BootstrapInstance{
					Name:          "test-instance",
					InstanceToken: "test-token",
					OSArch:        params.Amd64,
					OSType:        params.Linux,
					Image:         "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest",
					Flavor:        "Standard_DS13_v2",
					Tools: []params.RunnerApplicationDownload{
						{
							OS:                to.Ptr("linux"),
							Architecture:      to.Ptr("x64"),
							DownloadURL:       to.Ptr("http://test.com"),
							Filename:          to.Ptr("runner.tar.gz"),
							SHA256Checksum:    to.Ptr("sha256:1123"),
							TempDownloadToken: to.Ptr("test-token"),
						},
					},
					ExtraSpecs: json.RawMessage(`{}`),
				},
				Tools: params.RunnerApplicationDownload{
					OS:                to.Ptr("linux"),
					Architecture:      to.Ptr("x64"),
					DownloadURL:       to.Ptr("http://test.com"),
					Filename:          to.Ptr("runner.tar.gz"),
					SHA256Checksum:    to.Ptr("sha256:1123"),
					TempDownloadToken: to.Ptr("test-token"),
				},
				Tags: map[string]*string{
					"tag1": to.Ptr("value1"),
					"tag2": to.Ptr("value2"),
				},
				SSHPublicKeys:            []string{},
				Confidential:             true,
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},
			errString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := a.CreateNetworkSecurityGroup(ctx, baseName, tt.spec)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, baseName, *resp.Name)
				assert.NotNil(t, resp.Properties.SecurityRules)
			}
		})
	}
}

func TestCreateNetWorkInterface(t *testing.T) {
	ctx := context.Background()
	baseName := "test"
	subnetID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"
	nsgID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/nsg-test"
	pubPID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/publicIPAddresses/pip-test"
	myNetworkInterfaceServer := armnetworkfake.InterfacesServer{}
	myNetworkInterfaceServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, networkInterfaceName string, parameters armnetwork.Interface, options *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.InterfacesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armnetwork.InterfacesClientCreateOrUpdateResponse{
			Interface: armnetwork.Interface{
				ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkInterfaces/nic-test"),
				Name: to.Ptr(baseName),
				Properties: &armnetwork.InterfacePropertiesFormat{
					EnableAcceleratedNetworking: to.Ptr(true),
					EnableIPForwarding:          to.Ptr(false),
					NetworkSecurityGroup: &armnetwork.SecurityGroup{
						ID: to.Ptr(nsgID),
					},
					IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
						{
							Name: to.Ptr("ipconfig1"),
							Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
								PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
								Subnet: &armnetwork.Subnet{
									ID: to.Ptr(subnetID),
								},
								PublicIPAddress: &armnetwork.PublicIPAddress{
									ID: to.Ptr(pubPID),
								},
							},
						},
					},
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armnetwork.NewInterfacesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewInterfacesServerTransport(&myNetworkInterfaceServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		nicCli: client,
	}

	resp, err := a.CreateNetWorkInterface(ctx, baseName, subnetID, pubPID, nsgID, false)
	assert.NoError(t, err)
	assert.Equal(t, baseName, *resp.Name)
	assert.NotNil(t, resp.Properties.NetworkSecurityGroup)
	assert.NotNil(t, resp.Properties.IPConfigurations)
	assert.NotNil(t, resp.Properties.IPConfigurations[0].Properties.PublicIPAddress)
	assert.Equal(t, pubPID, *resp.Properties.IPConfigurations[0].Properties.PublicIPAddress.ID)
}

func TestCreatePublicIP(t *testing.T) {
	ctx := context.Background()
	baseName := "test"
	myPublicIPAdressesServer := armnetworkfake.PublicIPAddressesServer{}
	myPublicIPAdressesServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, publicIPAddressName string, parameters armnetwork.PublicIPAddress, options *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armnetwork.PublicIPAddressesClientCreateOrUpdateResponse{
			PublicIPAddress: armnetwork.PublicIPAddress{
				Location: to.Ptr("eastus"),
				Properties: &armnetwork.PublicIPAddressPropertiesFormat{
					PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armnetwork.NewPublicIPAddressesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewPublicIPAddressesServerTransport(&myPublicIPAdressesServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		pubIPCli: client,
	}

	resp, err := a.CreatePublicIP(ctx, baseName)
	assert.NoError(t, err)
	assert.Equal(t, "eastus", *resp.Location)
	assert.Equal(t, armnetwork.IPAllocationMethodStatic, *resp.Properties.PublicIPAllocationMethod)
}

func TestCreateVirtualMachine(t *testing.T) {
	ctx := context.Background()
	nicID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkInterfaces/nic-test"
	storageAccountID := "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Storage/storageAccounts/st-test"
	sizeSpec := spec.VMSizeEphemeralDiskSizeLimits{
		ResourceDiskSizeGB: 128,
		CacheDiskSizeGB:    0,
	}
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	myVirtualMachineServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachine, options *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armcompute.VirtualMachinesClientCreateOrUpdateResponse{
			VirtualMachine: armcompute.VirtualMachine{
				ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
				Name: to.Ptr("test-instance"),
				Properties: &armcompute.VirtualMachineProperties{
					StorageProfile: &armcompute.StorageProfile{
						ImageReference: &armcompute.ImageReference{
							Publisher: to.Ptr("Canonical"),
							Offer:     to.Ptr("0001-com-ubuntu-server-jammy"),
							SKU:       to.Ptr("22_04-lts-gen2"),
							Version:   to.Ptr("latest"),
						},
						OSDisk: &armcompute.OSDisk{
							ManagedDisk: &armcompute.ManagedDiskParameters{
								ID: to.Ptr(storageAccountID),
							},
						},
					},
					NetworkProfile: &armcompute.NetworkProfile{
						NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
							{
								ID: to.Ptr(nicID),
							},
						},
					},
				},
			},
		}, nil)
		return resp, errResp
	}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		vmCli: client,
	}

	tests := []struct {
		name      string
		spec      *spec.RunnerSpec
		errString string
	}{
		{
			name:      "invalid spec",
			spec:      nil,
			errString: "invalid nil runner spec",
		},
		{
			name: "valid spec",
			spec: &spec.RunnerSpec{
				VMSize:             "Standard_DS2_v2",
				AllocatePublicIP:   true,
				AdminUsername:      "admin",
				StorageAccountType: "Standard_LRS",
				DiskSizeGB:         128,
				OpenInboundPorts: map[armnetwork.SecurityRuleProtocol][]int{
					armnetwork.SecurityRuleProtocolTCP: {22, 80},
					armnetwork.SecurityRuleProtocolUDP: {53},
				},
				BootstrapParams: params.BootstrapInstance{
					Name:          "test-instance",
					InstanceToken: "test-token",
					OSArch:        params.Amd64,
					OSType:        params.Linux,
					Image:         "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest",
					Flavor:        "Standard_DS13_v2",
					Tools: []params.RunnerApplicationDownload{
						{
							OS:                to.Ptr("linux"),
							Architecture:      to.Ptr("x64"),
							DownloadURL:       to.Ptr("http://test.com"),
							Filename:          to.Ptr("runner.tar.gz"),
							SHA256Checksum:    to.Ptr("sha256:1123"),
							TempDownloadToken: to.Ptr("test-token"),
						},
					},
					ExtraSpecs: json.RawMessage(`{}`),
				},
				Tools: params.RunnerApplicationDownload{
					OS:                to.Ptr("linux"),
					Architecture:      to.Ptr("x64"),
					DownloadURL:       to.Ptr("http://test.com"),
					Filename:          to.Ptr("runner.tar.gz"),
					SHA256Checksum:    to.Ptr("sha256:1123"),
					TempDownloadToken: to.Ptr("test-token"),
				},
				Tags: map[string]*string{
					"tag1": to.Ptr("value1"),
					"tag2": to.Ptr("value2"),
				},
				SSHPublicKeys:            []string{},
				Confidential:             true,
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},
			errString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := a.CreateVirtualMachine(ctx, tt.spec, nicID, sizeSpec)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetMaxEphemeralDiskSize(t *testing.T) {
	ctx := context.Background()
	vmSize := "Standard_DS2_v2"
	myResourceSKUsServer := armcomputefake.ResourceSKUsServer{}
	client, err := armcompute.NewResourceSKUsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewResourceSKUsServerTransport(&myResourceSKUsServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		resourceSKUCli: client,
	}

	tests := []struct {
		name      string
		respCode  int
		expected  spec.VMSizeEphemeralDiskSizeLimits
		errString string
	}{
		{
			name:     "get vm size",
			respCode: 200,
			expected: spec.VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 128,
				CacheDiskSizeGB:    0,
			},
			errString: "",
		},
		{
			name:      "get vm size failed",
			respCode:  404,
			errString: "failed to get VM size details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myResourceSKUsServer.NewListPager = func(options *armcompute.ResourceSKUsClientListOptions) (resp azfake.PagerResponder[armcompute.ResourceSKUsClientListResponse]) {
				mockResponse := armcompute.ResourceSKUsClientListResponse{
					ResourceSKUsResult: armcompute.ResourceSKUsResult{
						Value: []*armcompute.ResourceSKU{
							{
								Name:         to.Ptr("Standard_DS2_v2"),
								ResourceType: to.Ptr("virtualMachines"),
								Capabilities: []*armcompute.ResourceSKUCapabilities{
									{
										Name:  to.Ptr("EphemeralOSDiskSupported"),
										Value: to.Ptr("True"),
									},
									{
										Name:  to.Ptr("MaxResourceVolumeMB"),
										Value: to.Ptr("131072"),
									},
								},
							},
						},
					},
				}

				resp.AddPage(tt.respCode, mockResponse, nil)

				return resp
			}
			resp, err := a.GetMaxEphemeralDiskSize(ctx, vmSize)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, resp)
			}
		})
	}
}

func TestDeleteResourceGroup(t *testing.T) {
	ctx := context.Background()
	resourceGroup := "test"
	myResouceGroupServer := armresourcesfake.ResourceGroupsServer{}
	myResouceGroupServer.BeginDelete = func(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (resp azfake.PollerResponder[armresources.ResourceGroupsClientDeleteResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armresources.ResourceGroupsClientDeleteResponse{}, nil)
		return resp, errResp
	}
	client, err := armresources.NewResourceGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armresourcesfake.NewResourceGroupsServerTransport(&myResouceGroupServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		rgCli: client,
	}

	err = a.DeleteResourceGroup(ctx, resourceGroup, true)
	assert.NoError(t, err)
}

func TestGetInstance(t *testing.T) {
	ctx := context.Background()
	vmName := "test"
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		vmCli: client,
	}

	tests := []struct {
		name      string
		respCode  int
		expected  armcompute.VirtualMachine
		errString string
	}{
		{
			name:     "get vm",
			respCode: 200,
			expected: armcompute.VirtualMachine{
				ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
				Name: to.Ptr(vmName),
			},
			errString: "",
		},
		{
			name:      "get vm failed",
			respCode:  500,
			errString: "failed to get VM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myVirtualMachineServer.Get = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (resp azfake.Responder[armcompute.VirtualMachinesClientGetResponse], errResp azfake.ErrorResponder) {
				resp.SetResponse(tt.respCode, armcompute.VirtualMachinesClientGetResponse{
					VirtualMachine: armcompute.VirtualMachine{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr(vmName),
					},
				}, nil)
				return resp, errResp
			}

			resp, err := a.GetInstance(ctx, vmName)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, vmName, *resp.Name)
			}
		})
	}
}

func TestDealocateVM(t *testing.T) {
	ctx := context.Background()
	vmName := "test"
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		vmCli: client,
	}

	tests := []struct {
		name      string
		respCode  int
		errString string
	}{
		{
			name:      "dealocate vm",
			respCode:  200,
			errString: "",
		},
		{
			name:      "dealocate vm failed",
			respCode:  500,
			errString: "failed to dealocate VM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myVirtualMachineServer.BeginDeallocate = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginDeallocateOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientDeallocateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCode, armcompute.VirtualMachinesClientDeallocateResponse{}, nil)
				return resp, errResp
			}

			err := a.DealocateVM(ctx, vmName)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestStartVM(t *testing.T) {
	ctx := context.Background()
	vmName := "test"
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		vmCli: client,
	}

	tests := []struct {
		name      string
		respCode  int
		errString string
	}{
		{
			name:      "start vm",
			respCode:  200,
			errString: "",
		},
		{
			name:      "start vm failed",
			respCode:  500,
			errString: "failed to start VM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myVirtualMachineServer.BeginStart = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginStartOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientStartResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCode, armcompute.VirtualMachinesClientStartResponse{}, nil)
				return resp, errResp
			}

			err := a.StartVM(ctx, vmName)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListVirtualMachines(t *testing.T) {
	ctx := context.Background()
	poolID := "garm-pool-id"
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	myVirtualMachineServer.NewListAllPager = func(options *armcompute.VirtualMachinesClientListAllOptions) (resp azfake.PagerResponder[armcompute.VirtualMachinesClientListAllResponse]) {
		resp.AddPage(200, armcompute.VirtualMachinesClientListAllResponse{
			VirtualMachineListResult: armcompute.VirtualMachineListResult{
				Value: []*armcompute.VirtualMachine{
					{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr("vm-test"),
						Tags: map[string]*string{"garm-pool-id": &poolID},
					},
				},
			},
		}, nil)
		return resp
	}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	a := AzureCli{
		cfg: &config.Config{
			Credentials: config.Credentials{
				SubscriptionID: "subscriptionID",
				SPCredentials: config.ServicePrincipalCredentials{
					TenantID:     "tenantID",
					ClientID:     "clientID",
					ClientSecret: "clientSecret",
				},
				ManagedIdentity: config.ManagedIdentityCredentials{
					ClientID: "clientID",
				},
			},
			Location:                 "eastus",
			UseEphemeralStorage:      true,
			VirtualNetworkCIDR:       "10.10.0.0/24",
			UseAcceleratedNetworking: true,
			VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			DisableIsolatedNetworks:  true,
		},
		vmCli: client,
	}
	tests := []struct {
		name     string
		poolID   string
		expected []*armcompute.VirtualMachine
	}{
		{
			name:     "no virtual machines with pool id",
			poolID:   "bad-pool-id",
			expected: []*armcompute.VirtualMachine(nil),
		},
		{
			name:   "virtual machines with pool id",
			poolID: poolID,
			expected: []*armcompute.VirtualMachine{
				{
					ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
					Name: to.Ptr("vm-test"),
					Tags: map[string]*string{"garm-pool-id": &poolID},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := a.ListVirtualMachines(ctx, tt.poolID)
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, resp)
		})
	}
}
