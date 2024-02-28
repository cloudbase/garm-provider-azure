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

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
				OS:                ptr("linux"),
				Architecture:      ptr("x64"),
				DownloadURL:       ptr("http://test.com"),
				Filename:          ptr("runner.tar.gz"),
				SHA256Checksum:    ptr("sha256:1123"),
				TempDownloadToken: ptr("test-token"),
			},
		},
	}

	tests := []struct {
		name       string
		extraspecs extraSpecs
		cfg        *config.Config
		want       *RunnerSpec
		wantErr    bool
	}{
		{
			name: "only defaults",
			cfg:  &config.Config{},
			want: &RunnerSpec{},
		},
		{
			name: "only config - no extra specs",
			cfg: &config.Config{
				UseEphemeralStorage:      true,
				UseAcceleratedNetworking: true,
				DisableIsolatedNetworks:  true,
			},
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
			extraspecs: extraSpecs{
				UseEphemeralStorage:      ptr(false),
				UseAcceleratedNetworking: ptr(false),
				DisableIsolatedNetworks:  ptr(false),
			},
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
			extraspecs: extraSpecs{
				UseEphemeralStorage:      ptr(false),
				UseAcceleratedNetworking: ptr(false),
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
			},

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
			extraspecs: extraSpecs{
				VnetSubnetID:            "broken",
				DisableIsolatedNetworks: ptr(true),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawMessage, err := json.Marshal(tt.extraspecs)
			if err != nil {
				t.Errorf("error marshalling extraSpecs: %v", err)
			}

			bootstrapParams.ExtraSpecs = rawMessage

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

func ptr[T any](v T) *T {
	return &v
}
