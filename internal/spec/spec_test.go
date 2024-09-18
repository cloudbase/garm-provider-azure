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

package spec

import (
	"encoding/json"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-common/cloudconfig"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewExtraSpecsFromBootstrapData(t *testing.T) {
	tests := []struct {
		name      string
		input     json.RawMessage
		want      *extraSpecs
		errString string
	}{
		{
			name: "extra specs with all fields",
			input: json.RawMessage(`{
				"allocate_public_ip": true,
				"confidential": true,
				"use_ephemeral_storage": true,
				"use_accelerated_networking": true,
				"open_inbound_ports": {
					"Tcp": [22, 80],
					"Udp": [53]
				},
				"storage_account_type": "Standard_LRS",
				"virtual_network_cidr": "10.10.0.0/16",
				"disk_size_gb": 128,
				"extra_tags": {
					"tag1": "value1",
					"tag2": "value2"
				},
				"ssh_public_keys": ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfz1z7"],
				"vnet_subnet_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				"disable_isolated_networks": true,
				"disable_updates": true,
				"enable_boot_debug": true,
				"extra_packages": ["package1", "package2"],
				"runner_install_template": "IyEvYmluL2Jhc2gKZWNobyBJbnN0YWxsaW5nIHJ1bm5lci4uLg==",
				"pre_install_scripts": {"setup.sh": "IyEvYmluL2Jhc2gKZWNobyBTZXR1cCBzY3JpcHQuLi4="},
				"extra_context": {"key": "value"}
			}`),
			want: &extraSpecs{
				AllocatePublicIP:         true,
				Confidential:             true,
				UseEphemeralStorage:      to.Ptr(true),
				UseAcceleratedNetworking: to.Ptr(true),
				OpenInboundPorts: map[armnetwork.SecurityRuleProtocol][]int{
					armnetwork.SecurityRuleProtocolTCP: {22, 80},
					armnetwork.SecurityRuleProtocolUDP: {53},
				},
				StorageAccountType: "Standard_LRS",
				VirtualNetworkCIDR: "10.10.0.0/16",
				DiskSizeGB:         128,
				ExtraTags: map[string]string{
					"tag1": "value1",
					"tag2": "value2",
				},
				SSHPublicKeys:           []string{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfz1z7"},
				VnetSubnetID:            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks: to.Ptr(true),
				DisableUpdates:          to.Ptr(true),
				EnableBootDebug:         to.Ptr(true),
				ExtraPackages:           []string{"package1", "package2"},
				CloudConfigSpec: cloudconfig.CloudConfigSpec{
					RunnerInstallTemplate: []byte("#!/bin/bash\necho Installing runner..."),
					PreInstallScripts: map[string][]byte{
						"setup.sh": []byte("#!/bin/bash\necho Setup script..."),
					},
					ExtraContext: map[string]string{"key": "value"},
				},
			},
			errString: "",
		},
		{
			name:  "empty BootstrapData - no extra specs",
			input: json.RawMessage(`{}`),
			want: &extraSpecs{
				OpenInboundPorts:   map[armnetwork.SecurityRuleProtocol][]int{},
				StorageAccountType: "Standard_LRS",
				ExtraTags:          map[string]string{},
			},
			errString: "",
		},
		{
			name: "invalid json",
			input: json.RawMessage(`{
				"allocate_public_ip":
			}`),
			want:      nil,
			errString: "failed to validate extra specs",
		},
		{
			name: "invalid input - allocate_public_ip - wrong data type",
			input: json.RawMessage(`{
				"allocate_public_ip": "true"
			}`),
			want:      nil,
			errString: "allocate_public_ip: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - open_inbound_ports - wrong data type",
			input: json.RawMessage(`{
				"open_inbound_ports": "true"
			}`),
			want:      nil,
			errString: "open_inbound_ports: Invalid type. Expected: object, given: string",
		},
		{
			name: "invalid input - StorageAccountType - wrong data type",
			input: json.RawMessage(`{
				"storage_account_type": true
			}`),
			want:      nil,
			errString: "storage_account_type: Invalid type. Expected: string, given: boolean",
		},
		{
			name: "invalid input - DiskSizeGB - wrong data type",
			input: json.RawMessage(`{
				"disk_size_gb": "128"
			}`),
			want:      nil,
			errString: "disk_size_gb: Invalid type. Expected: integer, given: string",
		},
		{
			name: "invalid input - ExtraTags - wrong data type",
			input: json.RawMessage(`{
				"extra_tags": ["tag1", "value1"]
			}`),
			want:      nil,
			errString: "extra_tags: Invalid type. Expected: object, given: array",
		},
		{
			name: "invalid input - SSHPublicKeys - wrong data type",
			input: json.RawMessage(`{
				"ssh_public_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDfz1z7"
			}`),
			want:      nil,
			errString: "ssh_public_keys: Invalid type. Expected: array, given: string",
		},
		{
			name: "invalid input - Confidential - wrong data type",
			input: json.RawMessage(`{
				"confidential": "true"
			}`),
			want:      nil,
			errString: "confidential: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - UseEphemeralStorage - wrong data type",
			input: json.RawMessage(`{
				"use_ephemeral_storage": "true"
			}`),
			want:      nil,
			errString: "use_ephemeral_storage: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - VirtualNetworkCIDR - wrong data type",
			input: json.RawMessage(`{
				"virtual_network_cidr": true
			}`),
			want:      nil,
			errString: "virtual_network_cidr: Invalid type. Expected: string, given: boolean",
		},
		{
			name: "invalid input - UseAcceleratedNetworking - wrong data type",
			input: json.RawMessage(`{
				"use_accelerated_networking": "true"
			}`),
			want:      nil,
			errString: "use_accelerated_networking: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - VnetSubnetID - wrong data type",
			input: json.RawMessage(`{
				"vnet_subnet_id": true
			}`),
			want:      nil,
			errString: "vnet_subnet_id: Invalid type. Expected: string, given: boolean",
		},
		{
			name: "invalid input - DisableIsolatedNetworks - wrong data type",
			input: json.RawMessage(`{
				"disable_isolated_networks": "true"
			}`),
			want:      nil,
			errString: "disable_isolated_networks: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - DisableUpdates - wrong data type",
			input: json.RawMessage(`{
				"disable_updates": "true"
			}`),
			want:      nil,
			errString: "disable_updates: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - EnableBootDebug - wrong data type",
			input: json.RawMessage(`{
				"enable_boot_debug": "true"
			}`),
			want:      nil,
			errString: "enable_boot_debug: Invalid type. Expected: boolean, given: string",
		},
		{
			name: "invalid input - RunnerInstallTemplate - wrong data type",
			input: json.RawMessage(`{
				"runner_install_template": true
			}`),
			want:      nil,
			errString: "runner_install_template: Invalid type. Expected: string, given: boolean",
		},
		{
			name: "invalid input - PreInstallScripts - wrong data type",
			input: json.RawMessage(`{
				"pre_install_scripts": true
			}`),
			want:      nil,
			errString: "pre_install_scripts: Invalid type. Expected: object, given: boolean",
		},
		{
			name: "invalid input - ExtraContext - wrong data type",
			input: json.RawMessage(`{
				"extra_context": true
			}`),
			want:      nil,
			errString: "extra_context: Invalid type. Expected: object, given: boolean",
		},
	}

	for _, tt := range tests {
		input := params.BootstrapInstance{
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
			ExtraSpecs: tt.input,
		}
		t.Run(tt.name, func(t *testing.T) {
			got, err := newExtraSpecsFromBootstrapData(input)
			if tt.errString == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			}
			assert.Equal(t, tt.want, got)
		})
	}

}

func TestGetRunnerSpecFromBootstrapParams(t *testing.T) {
	// this tests if the config parameters are correctly applied and verified
	// and if the extra specs override the default ones as expected
	// Beware: the config is not validated here in this test setup

	bootstrapParams := params.BootstrapInstance{
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
	}

	tests := []struct {
		name       string
		extraspecs json.RawMessage
		cfg        *config.Config
		want       *RunnerSpec
		wantErr    bool
	}{
		{
			name:       "only defaults",
			cfg:        &config.Config{},
			extraspecs: json.RawMessage(`{}`),
			want:       &RunnerSpec{},
		},
		{
			name: "only config - no extra specs",
			cfg: &config.Config{
				UseEphemeralStorage:      true,
				UseAcceleratedNetworking: true,
				DisableIsolatedNetworks:  true,
			},
			extraspecs: json.RawMessage(`{}`),
			want: &RunnerSpec{
				UseEphemeralStorage:      true,
				UseAcceleratedNetworking: true,
				DisableIsolatedNetworks:  true,
			},
		},
		{
			name: "override via extra specs",
			cfg: &config.Config{
				UseEphemeralStorage:      true,
				UseAcceleratedNetworking: true,
				DisableIsolatedNetworks:  true,
			},
			extraspecs: json.RawMessage(`{
				"use_ephemeral_storage": false,
				"use_accelerated_networking": false,
				"disable_isolated_networks": false
			}`),
			want: &RunnerSpec{
				UseEphemeralStorage:      false,
				UseAcceleratedNetworking: false,
				DisableIsolatedNetworks:  false,
			},
		},
		{
			name: "set vnetsubnetid via extra specs",
			cfg: &config.Config{
				UseEphemeralStorage:      true,
				UseAcceleratedNetworking: true,
				DisableIsolatedNetworks:  true,
			},
			extraspecs: json.RawMessage(`{
				"use_ephemeral_storage": false,
				"use_accelerated_networking": false,
				"vnet_subnet_id": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default"
			}`),
			want: &RunnerSpec{
				UseEphemeralStorage:      false,
				UseAcceleratedNetworking: false,
				DisableIsolatedNetworks:  true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			},
		},
		{
			name: "broken vnetsubnetid",
			cfg: &config.Config{
				// config is not validated here, hence we don't need to disable the isolated networks
				VnetSubnetID: "broken",
			},
			wantErr: true,
		},
		{
			name: "broken vnetsubnetid in extra specs",
			cfg:  &config.Config{},
			extraspecs: json.RawMessage(`{
				vnet_subnet_id: "broken",
				disable_isolated_networks: true
			}`),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			bootstrapParams.ExtraSpecs = tt.extraspecs

			got, err := GetRunnerSpecFromBootstrapParams(bootstrapParams, "test-controller", tt.cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, tt.want.UseEphemeralStorage, got.UseEphemeralStorage, "UseEphemeralStorage")
			assert.Equal(t, tt.want.UseAcceleratedNetworking, got.UseAcceleratedNetworking, "UseAcceleratedNetworking")
			assert.Equal(t, tt.want.DisableIsolatedNetworks, got.DisableIsolatedNetworks, "DisableIsolatedNetworks")
			assert.Equal(t, tt.want.VnetSubnetID, got.VnetSubnetID, "VNetSubnetID")
			assert.Equal(t, tt.want.SSHPublicKeys, got.SSHPublicKeys, "SSHPublicKeys")

			// as are marshalled and unmarshalled, the map might not nil, but empty
			if tt.want.OpenInboundPorts == nil {
				tt.want.OpenInboundPorts = map[armnetwork.SecurityRuleProtocol][]int{}
			}

			assert.Equal(t, tt.want.OpenInboundPorts, got.OpenInboundPorts, "OpenInboundPorts")
		})
	}
}

func TestRunnerSpecValidate(t *testing.T) {
	tests := []struct {
		name      string
		spec      *RunnerSpec
		errString string
	}{
		{
			name: "valid specs",
			spec: &RunnerSpec{
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
		{
			name: "missing flavour",
			spec: &RunnerSpec{
				VMSize: "",
			},
			errString: "missing flavor",
		},
		{
			name: "missing admin username",
			spec: &RunnerSpec{
				VMSize:        "Standard_DS2_v2",
				AdminUsername: "",
			},
			errString: "missing admin username",
		},
		{
			name: "missing storage account type",
			spec: &RunnerSpec{
				VMSize:             "Standard_DS2_v2",
				AdminUsername:      "admin",
				StorageAccountType: "",
			},
			errString: "missing storage account type",
		},
		{
			name: "invalid disk size",
			spec: &RunnerSpec{
				VMSize:              "Standard_DS2_v2",
				AdminUsername:       "admin",
				StorageAccountType:  "Standard_LRS",
				UseEphemeralStorage: false,
				DiskSizeGB:          0,
			},
			errString: "invalid disk size",
		},
		{
			name: "missing tools",
			spec: &RunnerSpec{
				VMSize:              "Standard_DS2_v2",
				AdminUsername:       "admin",
				StorageAccountType:  "Standard_LRS",
				UseEphemeralStorage: false,
				DiskSizeGB:          128,
				Tools:               params.RunnerApplicationDownload{},
			},
			errString: "missing tools",
		},
		{
			name: "invalid bootstrap params",
			spec: &RunnerSpec{
				VMSize:              "Standard_DS2_v2",
				AdminUsername:       "admin",
				StorageAccountType:  "Standard_LRS",
				UseEphemeralStorage: false,
				DiskSizeGB:          128,
				Tools: params.RunnerApplicationDownload{
					OS:                to.Ptr("linux"),
					Architecture:      to.Ptr("x64"),
					DownloadURL:       to.Ptr("http://test.com"),
					Filename:          to.Ptr("runner.tar.gz"),
					SHA256Checksum:    to.Ptr("sha256:1123"),
					TempDownloadToken: to.Ptr("test-token"),
				},
				BootstrapParams: params.BootstrapInstance{},
			},
			errString: "invalid bootstrap params",
		},
		{
			name: "invalid vnet subnet id",
			spec: &RunnerSpec{
				VMSize:              "Standard_DS2_v2",
				AdminUsername:       "admin",
				StorageAccountType:  "Standard_LRS",
				UseEphemeralStorage: false,
				DiskSizeGB:          128,
				Tools: params.RunnerApplicationDownload{
					OS:                to.Ptr("linux"),
					Architecture:      to.Ptr("x64"),
					DownloadURL:       to.Ptr("http://test.com"),
					Filename:          to.Ptr("runner.tar.gz"),
					SHA256Checksum:    to.Ptr("sha256:1123"),
					TempDownloadToken: to.Ptr("test-token"),
				},
				BootstrapParams: params.BootstrapInstance{
					Name:          "test-instance",
					OSType:        params.Linux,
					OSArch:        params.Amd64,
					InstanceToken: "test-token",
				},
				VnetSubnetID: "invalid",
			},
			errString: "invalid vnet subnet id: invalid",
		},
		{
			name: "failed to validate public key",
			spec: &RunnerSpec{
				VMSize:              "Standard_DS2_v2",
				AdminUsername:       "admin",
				StorageAccountType:  "Standard_LRS",
				UseEphemeralStorage: false,
				DiskSizeGB:          128,
				Tools: params.RunnerApplicationDownload{
					OS:                to.Ptr("linux"),
					Architecture:      to.Ptr("x64"),
					DownloadURL:       to.Ptr("http://test.com"),
					Filename:          to.Ptr("runner.tar.gz"),
					SHA256Checksum:    to.Ptr("sha256:1123"),
					TempDownloadToken: to.Ptr("test-token"),
				},
				BootstrapParams: params.BootstrapInstance{
					Name:          "test-instance",
					OSType:        params.Linux,
					OSArch:        params.Amd64,
					InstanceToken: "test-token",
				},
				VnetSubnetID:  "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				SSHPublicKeys: []string{"invalid"},
			},
			errString: "failed to validate public key invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.errString == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			}
		})
	}
}

func TestGetNewVMProprieties(t *testing.T) {
	tests := []struct {
		name               string
		spec               *RunnerSpec
		networkInterfaceID string
		sizeSpec           VMSizeEphemeralDiskSizeLimits
		errString          string
	}{
		{
			name: "valid specs",
			spec: &RunnerSpec{
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
				Confidential:             false,
				UseEphemeralStorage:      false,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},

			networkInterfaceID: "networkInterfaceID",
			sizeSpec: VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 128,
				CacheDiskSizeGB:    0,
			},
			errString: "",
		},
		{
			name: "error getting image details",
			spec: &RunnerSpec{
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
					Image:         "",
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
				Confidential:             false,
				UseEphemeralStorage:      false,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},

			networkInterfaceID: "networkInterfaceID",
			sizeSpec: VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 128,
				CacheDiskSizeGB:    0,
			},
			errString: "failed to getimage details",
		},
		{
			name: "error getting image details",
			spec: &RunnerSpec{
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
					OSType:        params.Unknown,
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
				Confidential:             false,
				UseEphemeralStorage:      false,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},

			networkInterfaceID: "networkInterfaceID",
			sizeSpec: VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 128,
				CacheDiskSizeGB:    0,
			},
			errString: "failed to compose userdata",
		},
		{
			name: "error missing vm size parameter",
			spec: &RunnerSpec{
				VMSize:             "",
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
				Confidential:             false,
				UseEphemeralStorage:      false,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},

			networkInterfaceID: "networkInterfaceID",
			sizeSpec: VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 128,
				CacheDiskSizeGB:    0,
			},
			errString: "missing vm size parameter",
		},
		{
			name: "error failed to get ephemeral settings",
			spec: &RunnerSpec{
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
				Confidential:             false,
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/16",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},

			networkInterfaceID: "networkInterfaceID",
			sizeSpec: VMSizeEphemeralDiskSizeLimits{
				ResourceDiskSizeGB: 0,
				CacheDiskSizeGB:    0,
			},
			errString: "failed to get ephemeral settings",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			properties, err := tt.spec.GetNewVMProperties(tt.networkInterfaceID, tt.sizeSpec)
			if tt.errString == "" {
				require.NoError(t, err)
				assert.Equal(t, tt.spec.BootstrapParams.Name, *properties.StorageProfile.OSDisk.Name)
				assert.Equal(t, tt.spec.DiskSizeGB, *properties.StorageProfile.OSDisk.DiskSizeGB)
				assert.Equal(t, tt.spec.StorageAccountType, *properties.StorageProfile.OSDisk.ManagedDisk.StorageAccountType)
				assert.Equal(t, armcompute.VirtualMachineSizeTypes(tt.spec.VMSize), *properties.HardwareProfile.VMSize)
				assert.Equal(t, tt.spec.BootstrapParams.Name, *properties.OSProfile.ComputerName)
				assert.Equal(t, tt.spec.AdminUsername, *properties.OSProfile.AdminUsername)
				assert.Equal(t, tt.networkInterfaceID, *properties.NetworkProfile.NetworkInterfaces[0].ID)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			}
		})
	}
}
