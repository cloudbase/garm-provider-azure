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

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name      string
		c         *Config
		errString string
	}{
		{
			name: "valid config",
			c: &Config{
				Credentials: Credentials{
					SubscriptionID: "subscriptionID",
					SPCredentials: ServicePrincipalCredentials{
						TenantID:     "tenantID",
						ClientID:     "clientID",
						ClientSecret: "clientSecret",
					},
					ManagedIdentity: ManagedIdentityCredentials{
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
			errString: "",
		},
		{
			name: "missing location",
			c: &Config{
				Credentials: Credentials{
					SubscriptionID: "subscriptionID",
					SPCredentials: ServicePrincipalCredentials{
						TenantID:     "tenantID",
						ClientID:     "clientID",
						ClientSecret: "clientSecret",
					},
					ManagedIdentity: ManagedIdentityCredentials{
						ClientID: "clientID",
					},
				},
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/24",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},
			errString: "missing location",
		},
		{
			name: "missing credentials",
			c: &Config{
				Location:                 "eastus",
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/24",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},
			errString: "failed to validate credentials",
		},
		{
			name: "invalid virtual_network_cidr",
			c: &Config{
				Credentials: Credentials{
					SubscriptionID: "subscriptionID",
					SPCredentials: ServicePrincipalCredentials{
						TenantID:     "tenantID",
						ClientID:     "clientID",
						ClientSecret: "clientSecret",
					},
					ManagedIdentity: ManagedIdentityCredentials{
						ClientID: "clientID",
					},
				},
				Location:                 "eastus",
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "300.300.300.300/24",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default",
				DisableIsolatedNetworks:  true,
			},
			errString: "invalid virtual_network_cidr",
		},
		{
			name: "invalid vnet_subnet_id",
			c: &Config{
				Credentials: Credentials{
					SubscriptionID: "subscriptionID",
					SPCredentials: ServicePrincipalCredentials{
						TenantID:     "tenantID",
						ClientID:     "clientID",
						ClientSecret: "clientSecret",
					},
					ManagedIdentity: ManagedIdentityCredentials{
						ClientID: "clientID",
					},
				},
				Location:                 "eastus",
				UseEphemeralStorage:      true,
				VirtualNetworkCIDR:       "10.10.0.0/24",
				UseAcceleratedNetworking: true,
				VnetSubnetID:             "invalid",
				DisableIsolatedNetworks:  true,
			},
			errString: "invalid vnet_subnet_id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.c.Validate()
			if tt.errString != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errString)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewConfig(t *testing.T) {
	mockData := `
	location = "westeurope"
	use_ephemeral_storage = true
	virtual_network_cidr = "10.10.0.0/24"
	use_accelerated_networking = true
	vnet_subnet_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default"
	disable_isolated_networks = true

	[credentials]
	subscription_id = "sample_sub_id"

	[credentials.workload_identity]
	tenant_id = "sample_tenant_id"
	client_id = "sample_client_id"
	federated_token_file = "/dev/null"

	# The service principle service credentials can be used when azure managed identity
	# is not available.
	[credentials.service_principal]
	# you can create a SP using:
	# az ad sp create-for-rbac --scopes /subscriptions/<subscription ID> --role Contributor
	tenant_id = "sample_tenant_id"
	client_id = "sample_client_id"
	client_secret = "super secret client secret"

	# The managed identity token source is always added to the chain of possible authentication
	# sources. The client ID can be overwritten if needed.
	[credentials.managed_identity]
	# The client ID to use. This config value is optional.
	client_id = "sample_client_id"
	`

	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "config-*.toml")
	require.NoError(t, err, "Failed to create temporary file")
	defer os.Remove(tmpFile.Name())

	_, err = tmpFile.WriteString(mockData)
	require.NoError(t, err, "Failed to write to temporary file")
	err = tmpFile.Close()
	require.NoError(t, err, "Failed to close temporary file")

	// Use the temporary file path as the argument to NewConfig
	cfg, err := NewConfig(tmpFile.Name())
	require.NoError(t, err, "NewConfig returned an error")

	// Validate the content of the Config object
	require.Equal(t, "westeurope", cfg.Location, "Location is not as expected")
	require.Equal(t, "sample_sub_id", cfg.Credentials.SubscriptionID, "SubscriptionID is not as expected")
	require.Equal(t, "sample_tenant_id", cfg.Credentials.SPCredentials.TenantID, "TenantID is not as expected")
	require.Equal(t, "sample_client_id", cfg.Credentials.SPCredentials.ClientID, "ClientID is not as expected")
	require.Equal(t, "super secret client secret", cfg.Credentials.SPCredentials.ClientSecret, "ClientSecret is not as expected")
	require.Equal(t, "sample_client_id", cfg.Credentials.ManagedIdentity.ClientID, "ManagedIdentity ClientID is not as expected")
	require.Equal(t, "sample_tenant_id", cfg.Credentials.WorkloadIdentity.TenantID, "WorkloadIdentity TenantID is not as expected")
	require.Equal(t, "sample_client_id", cfg.Credentials.WorkloadIdentity.ClientID, "WorkloadIdentity ClientID is not as expected")
	require.Equal(t, "/dev/null", cfg.Credentials.WorkloadIdentity.FederatedTokenFile, "WorkloadIdentity FederatedTokenFile is not as expected")

	require.True(t, cfg.UseEphemeralStorage, "UseEphemeralStorage is not as expected")
	require.Equal(t, "10.10.0.0/24", cfg.VirtualNetworkCIDR, "VirtualNetworkCIDR is not as expected")
	require.Equal(t, "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-Network/providers/Microsoft.Network/virtualNetworks/vnet-Default/subnets/snet-default", cfg.VnetSubnetID, "VnetSubnetID is not as expected")
	require.True(t, cfg.UseAcceleratedNetworking, "UseAcceleratedNetworking is not as expected")
	require.True(t, cfg.DisableIsolatedNetworks, "DisableIsolatedNetworks is not as expected")
}

func TestAbsentTokenFile(t *testing.T) {
	conf, err := NewConfig("../testdata/config_with_workload_identity.toml")
	require.Error(t, err, "NewConfig should return an error")
	require.Nil(t, conf)
}
