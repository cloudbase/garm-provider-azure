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

package util

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTagsFromBootstrapParams(t *testing.T) {
	tests := []struct {
		name            string
		bootstrapParams params.BootstrapInstance
		controllerID    string
		want            map[string]string
		errString       string
	}{
		{
			name: "valid",
			bootstrapParams: params.BootstrapInstance{
				Name:          "test-instance",
				InstanceToken: "test-token",
				OSArch:        params.Amd64,
				OSType:        params.Linux,
				Image:         "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:22.04.202206040",
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
				PoolID: "test-pool",
			},
			controllerID: "test-controller",
			want: map[string]string{
				"os_arch":           "amd64",
				"os_version":        "22.04.202206040",
				"os_name":           "22_04-lts-gen2",
				"os_type":           "linux",
				PoolIDTagName:       "test-pool",
				ControllerIDTagName: "test-controller",
			},
			errString: "",
		},
		{
			name: "invalid image",
			bootstrapParams: params.BootstrapInstance{
				Name:          "test-instance",
				InstanceToken: "test-token",
				OSArch:        params.Amd64,
				OSType:        params.Linux,
				Image:         "invalid",
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
				PoolID: "test-pool",
			},
			controllerID: "test-controller",
			want: map[string]string{
				"os_arch":           "amd64",
				"os_version":        "22.04.202206040",
				"os_name":           "22_04-lts-gen2",
				"os_type":           "linux",
				PoolIDTagName:       "test-pool",
				ControllerIDTagName: "test-controller",
			},
			errString: "failed to parse image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TagsFromBootstrapParams(tt.bootstrapParams, tt.controllerID)
			if err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)
				for k, v := range tt.want {
					assert.Equal(t, v, *got[k])
				}
			}
		})
	}
}

func TestURNToImageDetails(t *testing.T) {
	tests := []struct {
		name      string
		urn       string
		want      ImageDetails
		errString string
	}{
		{
			name: "valid",
			urn:  "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:22.04.202206040",
			want: ImageDetails{
				Offer:     "0001-com-ubuntu-server-jammy",
				Publisher: "Canonical",
				SKU:       "22_04-lts-gen2",
				Version:   "22.04.202206040",
			},
			errString: "",
		},
		{
			name: "Gallery reference",
			urn:  "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/galleries/gallery/images/image/versions/1.0.0",
			want: ImageDetails{
				ID:          "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.Compute/galleries/gallery/images/image/versions/1.0.0",
				IsCommunity: false,
			},
			errString: "",
		},
		{
			name:      "invalid",
			urn:       "invalid",
			want:      ImageDetails{},
			errString: "invalid image URN",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := URNToImageDetails(tt.urn)
			if err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestAzurePowerStateToGarmPowerState(t *testing.T) {
	tests := []struct {
		name          string
		vm            armcompute.VirtualMachine
		want          string
		provisioning  string
		instanceState string
	}{
		{
			name: "running",
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want: "running",
		},
		{
			name: "provisioning",
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					ProvisioningState: to.Ptr("Creating"),
				},
			},
			want: "pending_create",
		},
		{
			name: "unknown",
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/unknown"),
							},
						},
					},
				},
			},
			want: "unknown",
		},
		{
			name: "provisioning unknown",
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					ProvisioningState: to.Ptr("Unknown"),
				},
			},
			want: "unknown",
		},
		{
			name: "instance state unknown",
			vm: armcompute.VirtualMachine{
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/unknown"),
							},
						},
					},
				},
			},
			want: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AzurePowerStateToGarmPowerState(tt.vm)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAzureInstanceToParamsInstance(t *testing.T) {
	tests := []struct {
		name      string
		vm        armcompute.VirtualMachine
		want      params.ProviderInstance
		errString string
	}{
		{
			name: "valid",
			vm: armcompute.VirtualMachine{
				Name: to.Ptr("test-instance"),
				Tags: map[string]*string{
					"os_type":    to.Ptr("linux"),
					"os_arch":    to.Ptr("amd64"),
					"os_version": to.Ptr("22.04.202206040"),
					"os_name":    to.Ptr("22_04-lts-gen2"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want: params.ProviderInstance{
				ProviderID: "test-instance",
				Name:       "test-instance",
				OSType:     params.Linux,
				OSArch:     params.Amd64,
				OSName:     "22_04-lts-gen2",
				OSVersion:  "22.04.202206040",
				Status:     params.InstanceStatus("running"),
			},
			errString: "",
		},
		{
			name: "missing VM name",
			vm: armcompute.VirtualMachine{
				Tags: map[string]*string{
					"os_type":    to.Ptr("linux"),
					"os_arch":    to.Ptr("amd64"),
					"os_version": to.Ptr("22.04.202206040"),
					"os_name":    to.Ptr("22_04-lts-gen2"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want:      params.ProviderInstance{},
			errString: "missing VM name",
		},
		{
			name: "missing os_type tag",
			vm: armcompute.VirtualMachine{
				Name: to.Ptr("test-instance"),
				Tags: map[string]*string{
					"os_arch":    to.Ptr("amd64"),
					"os_version": to.Ptr("22.04.202206040"),
					"os_name":    to.Ptr("22_04-lts-gen2"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want:      params.ProviderInstance{},
			errString: "missing os_type tag in VM",
		},
		{
			name: "missing os_arch tag",
			vm: armcompute.VirtualMachine{
				Name: to.Ptr("test-instance"),
				Tags: map[string]*string{
					"os_type":    to.Ptr("linux"),
					"os_version": to.Ptr("22.04.202206040"),
					"os_name":    to.Ptr("22_04-lts-gen2"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want:      params.ProviderInstance{},
			errString: "missing os_arch tag in VM",
		},
		{
			name: "missing os_version tag",
			vm: armcompute.VirtualMachine{
				Name: to.Ptr("test-instance"),
				Tags: map[string]*string{
					"os_type": to.Ptr("linux"),
					"os_arch": to.Ptr("amd64"),
					"os_name": to.Ptr("22_04-lts-gen2"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want:      params.ProviderInstance{},
			errString: "missing os_version tag in VM",
		},
		{
			name: "missing os_name tag",
			vm: armcompute.VirtualMachine{
				Name: to.Ptr("test-instance"),
				Tags: map[string]*string{
					"os_type":    to.Ptr("linux"),
					"os_arch":    to.Ptr("amd64"),
					"os_version": to.Ptr("22.04.202206040"),
				},
				Properties: &armcompute.VirtualMachineProperties{
					InstanceView: &armcompute.VirtualMachineInstanceView{
						Statuses: []*armcompute.InstanceViewStatus{
							{
								Code: to.Ptr("PowerState/running"),
							},
						},
					},
				},
			},
			want:      params.ProviderInstance{},
			errString: "missing os_name tag in VM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AzureInstanceToParamsInstance(tt.vm)
			if err != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)

			}
			assert.Equal(t, tt.want, got)
		})
	}
}
