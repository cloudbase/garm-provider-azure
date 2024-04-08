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
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJsonSchemaValidation(t *testing.T) {
	tests := []struct {
		name      string
		input     json.RawMessage
		errString string
	}{
		{
			name: "valid extraSpecs",
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
				"disable_isolated_networks": true
			}`),
			errString: "",
		},
		{
			name: "bad input for use ephemeral storage",
			input: json.RawMessage(`{
				"allocate_public_ip": true,
				"confidential": true,
				"use_ephemeral_storage": "true",
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
				"disable_isolated_networks": true
			}`),
			errString: "Expected: boolean, given: string",
		},
		{
			name: "Bad schema format",
			input: json.RawMessage(`{
				"allocate_public_ip": true,
				"confidential": true,
				"use_ephemeral_storage": true,
				"use_accelerated_networking": true,
				"open_inbound_ports": {
					"Tcp": [22, 80],
					"Udp": [53],
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
				"disable_isolated_networks": true
			}`),
			errString: "invalid character '}' looking for beginning of object key string",
		},
		{
			name:      "empty input",
			input:     json.RawMessage(`{}`),
			errString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := jsonSchemaValidation(tt.input)
			if tt.errString == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			}
		})
	}
}

func TestNewExtraSpecsFromBootstrapData(t *testing.T) {
	tests := []struct {
		name      string
		input     params.BootstrapInstance
		want      *extraSpecs
		errString string
	}{
		{
			name: "empty BootstrapData - no extra specs",
			input: params.BootstrapInstance{
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
			want: &extraSpecs{
				OpenInboundPorts:   map[armnetwork.SecurityRuleProtocol][]int{},
				StorageAccountType: "Standard_LRS",
				ExtraTags:          map[string]string{},
			},
			errString: "",
		},
		{
			name: "extra specs with all fields",
			input: params.BootstrapInstance{
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
				ExtraSpecs: json.RawMessage(`{
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
					"disable_isolated_networks": true
				}`),
			},
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
			},
			errString: "",
		},
		{
			name: "bad input for use ephemeral storage",
			input: params.BootstrapInstance{
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
				ExtraSpecs: json.RawMessage(`{
					"use_ephemeral_storage": "broken"
				}`),
			},
			want:      nil,
			errString: "Expected: boolean, given: string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newExtraSpecsFromBootstrapData(tt.input)
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
