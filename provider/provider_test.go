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

package provider

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
	"github.com/cloudbase/garm-provider-azure/config"
	azclient "github.com/cloudbase/garm-provider-azure/internal/client"
	"github.com/cloudbase/garm-provider-azure/internal/spec"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	armresourcesfake "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/fake"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
)

func TestCreateInstance(t *testing.T) {
	ctx := context.Background()
	tags := map[string]*string{
		"controller-id": to.Ptr("controllerID"),
		"os_type":       to.Ptr("linux"),
		"os_arch":       to.Ptr("amd64"),
		"os_version":    to.Ptr("20.04"),
		"os_name":       to.Ptr("ubuntu"),
	}
	cfg := &config.Config{
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
		UseAcceleratedNetworking: true,
		DisableIsolatedNetworks:  true,
	}
	bootstrapParams := params.BootstrapInstance{
		Name:          "test-instance",
		InstanceToken: "test-token",
		OSArch:        params.Amd64,
		OSType:        params.Linux,
		Image:         "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest",
		Flavor:        "Standard_DS2_v2",
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
		ExtraSpecs: json.RawMessage(`{"allocate_public_ip": true}`),
	}

	myResourceSKUsServer := armcomputefake.ResourceSKUsServer{}
	skuClient, err := armcompute.NewResourceSKUsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewResourceSKUsServerTransport(&myResourceSKUsServer),
		},
	})
	assert.NoError(t, err)
	myResouceGroupServer := armresourcesfake.ResourceGroupsServer{}
	rgClient, err := armresources.NewResourceGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armresourcesfake.NewResourceGroupsServerTransport(&myResouceGroupServer),
		},
	})
	assert.NoError(t, err)
	myPublicIPAdressesServer := armnetworkfake.PublicIPAddressesServer{}
	pubIPClient, err := armnetwork.NewPublicIPAddressesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewPublicIPAddressesServerTransport(&myPublicIPAdressesServer),
		},
	})
	assert.NoError(t, err)
	mySecurityGroupServer := armnetworkfake.SecurityGroupsServer{}
	sgClient, err := armnetwork.NewSecurityGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewSecurityGroupsServerTransport(&mySecurityGroupServer),
		},
	})
	assert.NoError(t, err)
	myVirtualNetworkServer := armnetworkfake.VirtualNetworksServer{}
	vnetClient, err := armnetwork.NewVirtualNetworksClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewVirtualNetworksServerTransport(&myVirtualNetworkServer),
		},
	})
	assert.NoError(t, err)
	mySubnetServer := armnetworkfake.SubnetsServer{}
	subnetClient, err := armnetwork.NewSubnetsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewSubnetsServerTransport(&mySubnetServer),
		},
	})
	assert.NoError(t, err)
	myNetworkInterfaceServer := armnetworkfake.InterfacesServer{}
	nicClient, err := armnetwork.NewInterfacesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewInterfacesServerTransport(&myNetworkInterfaceServer),
		},
	})
	assert.NoError(t, err)
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	vmClient, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)

	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(rgClient, vnetClient, subnetClient, sgClient, nicClient, vmClient, pubIPClient, nil, skuClient)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}

	tests := []struct {
		name           string
		respCodeSKU    int
		respCodeRG     int
		respCodePubIP  int
		respCodeSG     int
		respCodeVNet   int
		respCodeSubNet int
		respCodeNIC    int
		respCodeVM     int
		osArch         params.OSArch
		expected       params.ProviderInstance
		errString      string
	}{
		{
			name:           "success",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected: params.ProviderInstance{
				ProviderID: "test-instance",
				Name:       "test-instance",
				OSType:     params.Linux,
				OSArch:     params.Amd64,
				OSName:     "22_04-lts-gen2",
				OSVersion:  "latest",
				Status:     "running",
			},
			errString: "",
		},
		{
			name:           "invalid architecture",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Arm,
			expected:       params.ProviderInstance{},
			errString:      "invalid architecture",
		},
		{
			name:           "failed to get max ephemeral disk size",
			respCodeSKU:    404,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to get max ephemeral disk size",
		},
		{
			name:           "failed to create resource group",
			respCodeSKU:    200,
			respCodeRG:     404,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to create resource group",
		},
		{
			name:           "failed to create public IP",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  404,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to create public IP",
		},
		{
			name:           "failed to create network security group",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     404,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to create network security group",
		},
		{
			name:           "failed to resolve subnet ID",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   404,
			respCodeSubNet: 404,
			respCodeNIC:    200,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to resolve subnet ID",
		},
		{
			name:           "failed to create NIC",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    404,
			respCodeVM:     200,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to create NIC",
		},
		{
			name:           "failed to create VM",
			respCodeSKU:    200,
			respCodeRG:     200,
			respCodePubIP:  200,
			respCodeSG:     200,
			respCodeVNet:   200,
			respCodeSubNet: 200,
			respCodeNIC:    200,
			respCodeVM:     404,
			osArch:         params.Amd64,
			expected:       params.ProviderInstance{},
			errString:      "failed to create VM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bootstrapParams.OSArch = tt.osArch
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
										Value: to.Ptr("1047552"),
									},
								},
							},
						},
					},
				}

				resp.AddPage(tt.respCodeSKU, mockResponse, nil)

				return resp
			}
			myResouceGroupServer.CreateOrUpdate = func(ctx context.Context, resourceGroupName string, parameters armresources.ResourceGroup, options *armresources.ResourceGroupsClientCreateOrUpdateOptions) (resp azfake.Responder[armresources.ResourceGroupsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetResponse(tt.respCodeRG, armresources.ResourceGroupsClientCreateOrUpdateResponse{
					ResourceGroup: armresources.ResourceGroup{
						ID:       to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test"),
						Name:     to.Ptr("rg-test"),
						Location: to.Ptr("eastus"),
						Tags:     tags,
					},
				}, nil)

				return resp, errResp
			}
			myPublicIPAdressesServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, publicIPAddressName string, parameters armnetwork.PublicIPAddress, options *armnetwork.PublicIPAddressesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.PublicIPAddressesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodePubIP, armnetwork.PublicIPAddressesClientCreateOrUpdateResponse{
					PublicIPAddress: armnetwork.PublicIPAddress{
						ID:       to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/publicIPAddresses/pip-test"),
						Location: to.Ptr("eastus"),
						Properties: &armnetwork.PublicIPAddressPropertiesFormat{
							PublicIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodStatic),
						},
					},
				}, nil)
				return resp, errResp
			}
			mySecurityGroupServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, networkSecurityGroupName string, parameters armnetwork.SecurityGroup, options *armnetwork.SecurityGroupsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.SecurityGroupsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeSG, armnetwork.SecurityGroupsClientCreateOrUpdateResponse{
					SecurityGroup: armnetwork.SecurityGroup{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/nsg-test"),
						Name: to.Ptr("nsg-test"),
						Properties: &armnetwork.SecurityGroupPropertiesFormat{
							SecurityRules: []*armnetwork.SecurityRule{},
						},
					},
				}, nil)
				return resp, errResp
			}
			myVirtualNetworkServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, parameters armnetwork.VirtualNetwork, options *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeVNet, armnetwork.VirtualNetworksClientCreateOrUpdateResponse{}, nil)
				return resp, errResp
			}
			mySubnetServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, subnetParameters armnetwork.Subnet, options *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.SubnetsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeSubNet, armnetwork.SubnetsClientCreateOrUpdateResponse{
					Subnet: armnetwork.Subnet{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"),
						Name: to.Ptr("snet-test"),
						Properties: &armnetwork.SubnetPropertiesFormat{
							AddressPrefix: to.Ptr("10.10.0.0/16"),
						},
					},
				}, nil)
				return resp, errResp
			}
			myNetworkInterfaceServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, networkInterfaceName string, parameters armnetwork.Interface, options *armnetwork.InterfacesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.InterfacesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeNIC, armnetwork.InterfacesClientCreateOrUpdateResponse{
					Interface: armnetwork.Interface{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkInterfaces/nic-test"),
						Name: to.Ptr("nic-test"),
						Properties: &armnetwork.InterfacePropertiesFormat{
							EnableAcceleratedNetworking: to.Ptr(true),
							EnableIPForwarding:          to.Ptr(false),
							NetworkSecurityGroup: &armnetwork.SecurityGroup{
								ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkSecurityGroups/nsg-test"),
							},
							IPConfigurations: []*armnetwork.InterfaceIPConfiguration{
								{
									Name: to.Ptr("ipconfig1"),
									Properties: &armnetwork.InterfaceIPConfigurationPropertiesFormat{
										PrivateIPAllocationMethod: to.Ptr(armnetwork.IPAllocationMethodDynamic),
										Subnet: &armnetwork.Subnet{
											ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"),
										},
										PublicIPAddress: &armnetwork.PublicIPAddress{
											ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/publicIPAddresses/pip-test"),
										},
									},
								},
							},
						},
					},
				}, nil)
				return resp, errResp
			}
			myVirtualMachineServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, vmName string, parameters armcompute.VirtualMachine, options *armcompute.VirtualMachinesClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeVM, armcompute.VirtualMachinesClientCreateOrUpdateResponse{
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
										ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/disks/disk-test"),
									},
								},
							},
							NetworkProfile: &armcompute.NetworkProfile{
								NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
									{
										ID: to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/networkInterfaces/nic-test"),
									},
								},
							},
						},
					},
				}, nil)
				return resp, errResp
			}
			instance, err := a.CreateInstance(ctx, bootstrapParams)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, instance)
		})
	}

}

func TestResolveSubnetID(t *testing.T) {
	ctx := context.Background()
	cfg := &config.Config{
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
	}
	myVirtualNetworkServer := armnetworkfake.VirtualNetworksServer{}
	vnetClient, err := armnetwork.NewVirtualNetworksClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewVirtualNetworksServerTransport(&myVirtualNetworkServer),
		},
	})
	assert.NoError(t, err)
	mySubnetServer := armnetworkfake.SubnetsServer{}
	subnetClient, err := armnetwork.NewSubnetsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armnetworkfake.NewSubnetsServerTransport(&mySubnetServer),
		},
	})
	assert.NoError(t, err)
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(nil, vnetClient, subnetClient, nil, nil, nil, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}
	runnerSpec := &spec.RunnerSpec{
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
	}

	tests := []struct {
		name                    string
		respCodeVNet            int
		respCodeSubnet          int
		DisableIsolatedNetworks bool
		expected                string
		errString               string
	}{
		{
			name:                    "success with disabled isolated networks",
			respCodeVNet:            200,
			respCodeSubnet:          200,
			DisableIsolatedNetworks: true,
			expected:                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			errString:               "",
		},
		{
			name:                    "success with enabled isolated networks",
			respCodeVNet:            200,
			respCodeSubnet:          200,
			DisableIsolatedNetworks: false,
			expected:                "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test",
		},
		{
			name:                    "failed to create vnet",
			respCodeVNet:            404,
			respCodeSubnet:          200,
			DisableIsolatedNetworks: false,
			expected:                "",
			errString:               "failed to create virtual network",
		},
		{
			name:                    "failed to create subnet",
			respCodeVNet:            200,
			respCodeSubnet:          404,
			DisableIsolatedNetworks: false,
			expected:                "",
			errString:               "failed to create subnet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runnerSpec.DisableIsolatedNetworks = tt.DisableIsolatedNetworks
			myVirtualNetworkServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, parameters armnetwork.VirtualNetwork, options *armnetwork.VirtualNetworksClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.VirtualNetworksClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeVNet, armnetwork.VirtualNetworksClientCreateOrUpdateResponse{}, nil)
				return resp, errResp
			}
			mySubnetServer.BeginCreateOrUpdate = func(ctx context.Context, resourceGroupName string, virtualNetworkName string, subnetName string, subnetParameters armnetwork.Subnet, options *armnetwork.SubnetsClientBeginCreateOrUpdateOptions) (resp azfake.PollerResponder[armnetwork.SubnetsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCodeSubnet, armnetwork.SubnetsClientCreateOrUpdateResponse{
					Subnet: armnetwork.Subnet{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Network/virtualNetworks/vnet-test/subnets/snet-test"),
						Name: to.Ptr("snet-test"),
						Properties: &armnetwork.SubnetPropertiesFormat{
							AddressPrefix: to.Ptr("10.10.0.0/16"),
						},
					},
				}, nil)
				return resp, errResp
			}
			subnetID, err := a.resolveSubnetID(ctx, runnerSpec)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, subnetID)
		})
	}

}

func TestDeleteInstance(t *testing.T) {
	ctx := context.Background()
	instance := "test-instance"
	cfg := &config.Config{
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
	}
	myResouceGroupServer := armresourcesfake.ResourceGroupsServer{}
	client, err := armresources.NewResourceGroupsClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armresourcesfake.NewResourceGroupsServerTransport(&myResouceGroupServer),
		},
	})
	assert.NoError(t, err)
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(client, nil, nil, nil, nil, nil, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}

	tests := []struct {
		name      string
		respCode  int
		errString string
	}{
		{
			name:      "success",
			respCode:  200,
			errString: "",
		},
		{
			name:      "failed to delete resource group",
			respCode:  404,
			errString: "failed to delete resource group",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myResouceGroupServer.BeginDelete = func(ctx context.Context, resourceGroupName string, options *armresources.ResourceGroupsClientBeginDeleteOptions) (resp azfake.PollerResponder[armresources.ResourceGroupsClientDeleteResponse], errResp azfake.ErrorResponder) {
				resp.SetTerminalResponse(tt.respCode, armresources.ResourceGroupsClientDeleteResponse{}, nil)
				return resp, errResp
			}
			err := a.DeleteInstance(ctx, instance)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetInstance(t *testing.T) {
	ctx := context.Background()
	instance := "test-instance"
	cfg := &config.Config{
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
	}
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(nil, nil, nil, nil, nil, client, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}

	tests := []struct {
		name      string
		instance  string
		expected  params.ProviderInstance
		respCode  int
		tags      map[string]*string
		errString string
	}{
		{
			name:     "success",
			instance: instance,
			expected: params.ProviderInstance{
				ProviderID: "test-instance",
				Name:       "test-instance",
				OSType:     "linux",
				OSArch:     "amd64",
				OSName:     "ubuntu",
				OSVersion:  "20.04",
				Status:     "running",
			},
			respCode: 200,
			tags: map[string]*string{
				"controller-id": to.Ptr("controllerID"),
				"os_type":       to.Ptr("linux"),
				"os_arch":       to.Ptr("amd64"),
				"os_version":    to.Ptr("20.04"),
				"os_name":       to.Ptr("ubuntu"),
			},
			errString: "",
		},
		{
			name:     "failed to get VM details",
			instance: "invalid-instance",
			expected: params.ProviderInstance{},
			respCode: 404,
			tags: map[string]*string{
				"controller-id": to.Ptr("controllerID"),
				"os_type":       to.Ptr("linux"),
				"os_arch":       to.Ptr("amd64"),
				"os_version":    to.Ptr("20.04"),
				"os_name":       to.Ptr("ubuntu"),
			},
			errString: "failed to get VM details",
		},
		{
			name:     "failed to get convert VM details",
			instance: instance,
			expected: params.ProviderInstance{},
			respCode: 200,
			tags: map[string]*string{
				"controller-id": to.Ptr("controllerID"),
				"os_type":       to.Ptr("linux"),
				"os_arch":       to.Ptr("amd64"),
				"os_name":       to.Ptr("ubuntu"),
			},
			errString: "failed to convert VM details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			myVirtualMachineServer.Get = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientGetOptions) (resp azfake.Responder[armcompute.VirtualMachinesClientGetResponse], errResp azfake.ErrorResponder) {
				resp.SetResponse(tt.respCode, armcompute.VirtualMachinesClientGetResponse{
					VirtualMachine: armcompute.VirtualMachine{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr(vmName),
						Tags: tt.tags,
						Properties: &armcompute.VirtualMachineProperties{
							ProvisioningState: to.Ptr("Succeeded"),
						},
					},
				}, nil)
				return resp, errResp
			}
			instance, err := a.GetInstance(ctx, tt.instance)
			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, instance)
		})
	}
}

func TestListInstances(t *testing.T) {
	ctx := context.Background()
	poolID := "poolID"
	cfg := &config.Config{
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
	}
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	myVirtualMachineServer.NewListAllPager = func(options *armcompute.VirtualMachinesClientListAllOptions) (resp azfake.PagerResponder[armcompute.VirtualMachinesClientListAllResponse]) {
		resp.AddPage(200, armcompute.VirtualMachinesClientListAllResponse{
			VirtualMachineListResult: armcompute.VirtualMachineListResult{
				Value: []*armcompute.VirtualMachine{
					{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr("vm-test"),
						Tags: map[string]*string{
							"garm-pool-id":  &poolID,
							"controller-id": to.Ptr("controllerID"),
							"os_type":       to.Ptr("linux"),
							"os_arch":       to.Ptr("amd64"),
							"os_version":    to.Ptr("20.04"),
							"os_name":       to.Ptr("ubuntu"),
						},
						Properties: &armcompute.VirtualMachineProperties{
							ProvisioningState: to.Ptr("Succeeded"),
						},
					},
					{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr("vm-test"),
						Tags: map[string]*string{
							"garm-pool-id":  &poolID,
							"controller-id": to.Ptr("controllerID"),
							"os_type":       to.Ptr("linux"),
							"os_arch":       to.Ptr("amd64"),
							"os_version":    to.Ptr("22.04"),
							"os_name":       to.Ptr("ubuntu"),
						},
						Properties: &armcompute.VirtualMachineProperties{
							ProvisioningState: to.Ptr("Succeeded"),
						},
					},
					{
						ID:   to.Ptr("/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test/providers/Microsoft.Compute/virtualMachines/vm-test"),
						Name: to.Ptr("vm-test"),
						Tags: map[string]*string{
							"garm-pool-id":  to.Ptr("bad-poolID"),
							"controller-id": to.Ptr("controllerID"),
							"os_type":       to.Ptr("linux"),
							"os_arch":       to.Ptr("amd64"),
						},
						Properties: &armcompute.VirtualMachineProperties{
							ProvisioningState: to.Ptr("Succeeded"),
						},
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
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(nil, nil, nil, nil, nil, client, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}
	tests := []struct {
		name      string
		poolID    string
		expected  []params.ProviderInstance
		errString string
	}{
		{
			name:   "success",
			poolID: poolID,
			expected: []params.ProviderInstance{
				{
					ProviderID: "vm-test",
					Name:       "vm-test",
					OSType:     "linux",
					OSArch:     "amd64",
					OSName:     "ubuntu",
					OSVersion:  "20.04",
					Status:     "running",
				},
				{
					ProviderID: "vm-test",
					Name:       "vm-test",
					OSType:     "linux",
					OSArch:     "amd64",
					OSName:     "ubuntu",
					OSVersion:  "22.04",
					Status:     "running",
				},
			},
			errString: "",
		},
		{
			name:      "error",
			poolID:    "invalid-poolID",
			expected:  []params.ProviderInstance{},
			errString: "",
		},
		{
			name:      "error",
			poolID:    "bad-poolID",
			expected:  []params.ProviderInstance(nil),
			errString: "failed to convert VM details",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instances, err := a.ListInstances(ctx, tt.poolID)

			if tt.errString != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.expected, instances)
		})
	}
}

func TestStop(t *testing.T) {
	ctx := context.Background()
	instance := "test-instance"
	cfg := &config.Config{
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
	}
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	myVirtualMachineServer.BeginDeallocate = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginDeallocateOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientDeallocateResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armcompute.VirtualMachinesClientDeallocateResponse{}, nil)
		return resp, errResp
	}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(nil, nil, nil, nil, nil, client, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}

	err = a.Stop(ctx, instance, true)
	assert.NoError(t, err)
}

func TestStart(t *testing.T) {
	ctx := context.Background()
	instance := "test-instance"
	cfg := &config.Config{
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
	}
	myVirtualMachineServer := armcomputefake.VirtualMachinesServer{}
	myVirtualMachineServer.BeginStart = func(ctx context.Context, resourceGroupName string, vmName string, options *armcompute.VirtualMachinesClientBeginStartOptions) (resp azfake.PollerResponder[armcompute.VirtualMachinesClientStartResponse], errResp azfake.ErrorResponder) {
		resp.SetTerminalResponse(200, armcompute.VirtualMachinesClientStartResponse{}, nil)
		return resp, errResp
	}
	client, err := armcompute.NewVirtualMachinesClient("fake-id", &azfake.TokenCredential{}, &policy.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: armcomputefake.NewVirtualMachinesServerTransport(&myVirtualMachineServer),
		},
	})
	assert.NoError(t, err)
	azCli := azclient.AzureCli{}
	azCli.SetConfig(cfg)
	azCli.SetLocation("eastus")
	azCli.SetClients(nil, nil, nil, nil, nil, client, nil, nil, nil)
	a := azureProvider{
		controllerID: "controllerID",
		azCli:        &azCli,
		cfg:          cfg,
	}

	err = a.Start(ctx, instance)
	assert.NoError(t, err)
}
