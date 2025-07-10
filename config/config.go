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
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/BurntSushi/toml"
)

// NewConfig returns a new Config
func NewConfig(cfgFile string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(cfgFile, &config); err != nil {
		return nil, fmt.Errorf("error decoding config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}
	return &config, nil
}

type Config struct {
	Credentials Credentials `toml:"credentials"`
	Location    string      `toml:"location"`
	// UseEphemeralStorage is a flag that indicates whether the provider should use
	// ephemeral storage for the VMs it creates. If true, the provider will use the
	// ephemeral OS disk feature to create the VMs. Note, the size of the ephemeral
	// OS disk is determined by the VM size, and the VM size must accomodate the size
	// of the image.
	UseEphemeralStorage      bool   `toml:"use_ephemeral_storage"`
	VirtualNetworkCIDR       string `toml:"virtual_network_cidr"`
	UseAcceleratedNetworking bool   `toml:"use_accelerated_networking"`
	VnetSubnetID             string `toml:"vnet_subnet_id"`
	DisableIsolatedNetworks  bool   `toml:"disable_isolated_networks"`
}

func (c *Config) Validate() error {
	if c.Location == "" {
		return fmt.Errorf("missing location")
	}
	if err := c.Credentials.Validate(); err != nil {
		return fmt.Errorf("failed to validate credentials: %w", err)
	}

	if c.VirtualNetworkCIDR != "" {
		if _, _, err := net.ParseCIDR(c.VirtualNetworkCIDR); err != nil {
			return fmt.Errorf("invalid virtual_network_cidr: %w", err)
		}
	}

	if c.DisableIsolatedNetworks {
		if err := ValidateVnetSubnet(c.VnetSubnetID); err != nil {
			return fmt.Errorf("invalid vnet_subnet_id: %w", err)
		}
	}

	return nil
}

type Credentials struct {
	SubscriptionID   string                      `toml:"subscription_id"`
	SPCredentials    ServicePrincipalCredentials `toml:"service_principal"`
	WorkloadIdentity WorkloadIdentityCredentials `toml:"workload_identity"`
	ManagedIdentity  ManagedIdentityCredentials  `toml:"managed_identity"`
	// ClientOptions is the azure identity client options that will be used to authenticate
	// against an azure cloud. This is a heavy handed approach for now, defining the entire
	// ClientOptions here, but should allow users to use this provider with AzureStack or any
	// other azure cloud besides Azure proper (like Azure China, Germany, etc).
	ClientOptions azcore.ClientOptions `toml:"client_options"`
}

func (c Credentials) Validate() error {
	if c.SubscriptionID == "" {
		return fmt.Errorf("missing subscription_id")
	}

	if _, err := c.GetCredentials(); err != nil {
		return fmt.Errorf("failed to validate credentials: %w", err)
	}

	return nil
}

var vnetSubnetRe = regexp.MustCompile(`/subscriptions/[a-f0-9-]{36}/resourceGroups/[a-zA-Z0-9-]+/providers/Microsoft.Network/virtualNetworks/[a-zA-Z0-9-]+/subnets/[a-zA-Z0-9-]+`)

func ValidateVnetSubnet(vnetSubnet string) error {
	if vnetSubnet == "" {
		return nil
	}

	if vnetSubnetRe.MatchString(vnetSubnet) {
		return nil
	}
	return fmt.Errorf("invalid vnet subnet, must match %s", vnetSubnetRe.String())
}

func (c Credentials) GetCredentials() (azcore.TokenCredential, error) {
	creds := []azcore.TokenCredential{}
	if spCreds, err := c.SPCredentials.Auth(c.ClientOptions); err == nil {
		creds = append(creds, spCreds)
	}

	// Let's try with Workload Identity first, since this is the preferred method nowadays.
	if c.WorkloadIdentity.ClientID != "" {
		wiOpts := &azidentity.WorkloadIdentityCredentialOptions{ClientOptions: c.ClientOptions}
		wiOpts.ClientID = c.WorkloadIdentity.ClientID
		if c.WorkloadIdentity.TenantID != "" {
			wiOpts.TenantID = c.WorkloadIdentity.TenantID
		}
		// NOTE: AuthorityHost is ignored for now
		if c.WorkloadIdentity.FederatedTokenFile != "" {
			if _, err := os.Stat(c.WorkloadIdentity.FederatedTokenFile); err != nil {
				return nil, fmt.Errorf("federated token file %s does not exist: %w", c.WorkloadIdentity.FederatedTokenFile, err)
			}
			wiOpts.TokenFilePath = c.WorkloadIdentity.FederatedTokenFile
		}
		wiCred, err := azidentity.NewWorkloadIdentityCredential(wiOpts)
		if err == nil {
			creds = append(creds, wiCred)
		}
	}

	// After Workload Identity is configured (or not), we can try Managed Identity.
	miOpts := &azidentity.ManagedIdentityCredentialOptions{ClientOptions: c.ClientOptions}
	if c.ManagedIdentity.ClientID != "" {
		miOpts.ID = azidentity.ClientID(c.ManagedIdentity.ClientID)
	}
	miCred, err := azidentity.NewManagedIdentityCredential(miOpts)
	if err == nil {
		creds = append(creds, miCred)
	}

	if len(creds) == 0 {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}

	chain, err := azidentity.NewChainedTokenCredential(creds, nil)
	if err != nil {
		return nil, err
	}

	return chain, nil
}

type ServicePrincipalCredentials struct {
	TenantID     string `toml:"tenant_id"`
	ClientID     string `toml:"client_id"`
	ClientSecret string `toml:"client_secret"`
}

func (c ServicePrincipalCredentials) Validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("missing tenant_id")
	}

	if c.ClientID == "" {
		return fmt.Errorf("missing client_id")
	}

	if c.ClientSecret == "" {
		return fmt.Errorf("missing client_secret")
	}

	return nil
}

func (c ServicePrincipalCredentials) Auth(opts azcore.ClientOptions) (azcore.TokenCredential, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating credentials: %w", err)
	}

	o := &azidentity.ClientSecretCredentialOptions{ClientOptions: opts}
	cred, err := azidentity.NewClientSecretCredential(c.TenantID, c.ClientID, c.ClientSecret, o)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

type WorkloadIdentityCredentials struct {
	TenantID           string `toml:"tenant_id"`
	ClientID           string `toml:"client_id"`
	FederatedTokenFile string `toml:"federated_token_file"`
	// AuthorityHost is not handled yet.
	// AuthorityHost      string `toml:"authority_host"`
}

type ManagedIdentityCredentials struct {
	ClientID string `toml:"client_id"`
}
