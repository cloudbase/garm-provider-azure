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
	"fmt"

	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-azure/internal/client"
	"github.com/cloudbase/garm-provider-azure/internal/spec"
	"github.com/cloudbase/garm-provider-azure/internal/util"

	"github.com/cloudbase/garm-provider-common/execution"
	"github.com/cloudbase/garm-provider-common/params"
)

var _ execution.ExternalProvider = &azureProvider{}

func NewAzureProvider(configPath, controllerID string) (execution.ExternalProvider, error) {
	conf, err := config.NewConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	azCli, err := client.NewAzCLI(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure CLI: %w", err)
	}
	return &azureProvider{
		controllerID: controllerID,
		azCli:        azCli,
		cfg:          conf,
	}, nil
}

type azureProvider struct {
	controllerID string
	azCli        *client.AzureCli
	cfg          *config.Config
}

// CreateInstance creates a new compute instance in the provider.
func (a *azureProvider) CreateInstance(ctx context.Context, bootstrapParams params.BootstrapInstance) (params.ProviderInstance, error) {
	if bootstrapParams.OSArch != params.Amd64 {
		// x86_64 only for now. Azure does seem to support arm64, which we will look at at a later time.
		return params.ProviderInstance{}, fmt.Errorf("invalid architecture %s (supported: %s)", bootstrapParams.OSArch, params.Amd64)
	}

	runnerSpec, err := spec.GetRunnerSpecFromBootstrapParams(bootstrapParams, a.controllerID, a.cfg)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to generate spec: %w", err)
	}

	imgDetails, err := runnerSpec.ImageDetails()
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to get image details: %w", err)
	}

	var sizeSpec spec.VMSizeEphemeralDiskSizeLimits
	if runnerSpec.UseEphemeralStorage {
		sizeSpec, err = a.azCli.GetMaxEphemeralDiskSize(ctx, runnerSpec.VMSize)
		if err != nil {
			return params.ProviderInstance{}, fmt.Errorf("failed to get max ephemeral disk size: %w", err)
		}

		diskSize := sizeSpec.CacheDiskSizeGB
		if diskSize == 0 {
			diskSize = sizeSpec.ResourceDiskSizeGB
		}

		// If confidential VMs are used with ephemeral storage, 1 GB is reserved.
		// See: https://learn.microsoft.com/en-us/azure/virtual-machines/ephemeral-os-disks#confidential-vms-using-ephemeral-os-disks
		// However, we disable confidential VMs for now, when ephemeral storage is used. We'll leave this recalculation of available
		// space, in case we enable it in the future.
		if runnerSpec.Confidential {
			diskSize = diskSize - 1
		}

		if diskSize < runnerSpec.DiskSizeGB {
			return params.ProviderInstance{}, fmt.Errorf("maximul ephemeral disk size for %s is %d GB (requested %d)", runnerSpec.VMSize, diskSize, runnerSpec.DiskSizeGB)
		}
	}

	_, err = a.azCli.CreateResourceGroup(ctx, runnerSpec.BootstrapParams.Name, runnerSpec.Tags)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to create resource group: %w", err)
	}

	defer func() {
		if err != nil {
			a.azCli.DeleteResourceGroup(ctx, runnerSpec.BootstrapParams.Name, true) //nolint
		}
	}()

	var pubIPID string
	var pubIP string
	if runnerSpec.AllocatePublicIP {
		publicIP, err := a.azCli.CreatePublicIP(ctx, runnerSpec.BootstrapParams.Name)
		if err != nil {
			return params.ProviderInstance{}, fmt.Errorf("failed to create public IP: %w", err)
		}
		if publicIP.Properties != nil && publicIP.Properties.IPAddress != nil {
			pubIP = *publicIP.Properties.IPAddress
		}
		pubIPID = *publicIP.ID
	}

	nsg, err := a.azCli.CreateNetworkSecurityGroup(ctx, runnerSpec.BootstrapParams.Name, runnerSpec)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to create network security group: %w", err)
	}

	subnetID, err := a.resolveSubnetID(ctx, runnerSpec)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to resolve subnet ID: %w", err)
	}

	nic, err := a.azCli.CreateNetWorkInterface(ctx, runnerSpec.BootstrapParams.Name, subnetID, *nsg.ID, pubIPID, runnerSpec.UseAcceleratedNetworking)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to create NIC: %w", err)
	}

	if err := a.azCli.CreateVirtualMachine(ctx, runnerSpec, *nic.ID, sizeSpec); err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to create VM: %w", err)
	}

	// We're lying here. It takes longer for the client to finish polling than for the VM to
	// start running the userdata. Just return that the instance is running once the request
	// to create it goes through.
	instance := params.ProviderInstance{
		ProviderID: runnerSpec.BootstrapParams.Name,
		Name:       runnerSpec.BootstrapParams.Name,
		OSType:     runnerSpec.BootstrapParams.OSType,
		OSArch:     runnerSpec.BootstrapParams.OSArch,
		OSName:     imgDetails.SKU,
		OSVersion:  imgDetails.Version,
		Status:     "running",
	}

	if pubIP != "" {
		instance.Addresses = append(instance.Addresses, params.Address{
			Address: pubIP,
			Type:    params.PublicAddress,
		})
	}
	return instance, nil
}

func (a *azureProvider) resolveSubnetID(ctx context.Context, runnerSpec *spec.RunnerSpec) (string, error) {
	if runnerSpec.VnetSubnetID != "" && runnerSpec.DisableIsolatedNetworks {
		return runnerSpec.VnetSubnetID, nil
	}

	_, err := a.azCli.CreateVirtualNetwork(ctx, runnerSpec.BootstrapParams.Name, runnerSpec.VirtualNetworkCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to create virtual network: %w", err)
	}

	subnet, err := a.azCli.CreateSubnet(ctx, runnerSpec.BootstrapParams.Name, runnerSpec.VirtualNetworkCIDR)
	if err != nil {
		return "", fmt.Errorf("failed to create subnet: %w", err)
	}

	return *subnet.ID, nil
}

// Delete instance will delete the instance in a provider.
func (a *azureProvider) DeleteInstance(ctx context.Context, instance string) error {
	err := a.azCli.DeleteResourceGroup(ctx, instance, true)
	if err != nil {
		return fmt.Errorf("failed to delete instance: %w", err)
	}
	return nil
}

// GetInstance will return details about one instance.
func (a *azureProvider) GetInstance(ctx context.Context, instance string) (params.ProviderInstance, error) {
	vm, err := a.azCli.GetInstance(ctx, instance)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to get VM details: %w", err)
	}
	details, err := util.AzureInstanceToParamsInstance(vm)
	if err != nil {
		return params.ProviderInstance{}, fmt.Errorf("failed to convert VM details: %w", err)
	}
	return details, nil
}

// ListInstances will list all instances for a provider.
func (a *azureProvider) ListInstances(ctx context.Context, poolID string) ([]params.ProviderInstance, error) {
	instances, err := a.azCli.ListVirtualMachines(ctx, poolID)
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}

	if instances == nil {
		return []params.ProviderInstance{}, nil
	}

	resp := make([]params.ProviderInstance, len(instances))
	for idx, val := range instances {
		if val == nil {
			return nil, fmt.Errorf("nil vm object in response")
		}
		details, err := util.AzureInstanceToParamsInstance(*val)
		if err != nil {
			return nil, fmt.Errorf("failed to convert VM details: %w", err)
		}
		resp[idx] = details
	}
	return resp, nil
}

// RemoveAllInstances will remove all instances created by this provider.
func (a *azureProvider) RemoveAllInstances(ctx context.Context) error {
	return nil
}

// Stop shuts down the instance.
func (a *azureProvider) Stop(ctx context.Context, instance string, force bool) error {
	return a.azCli.DealocateVM(ctx, instance)
}

// Start boots up an instance.
func (a *azureProvider) Start(ctx context.Context, instance string) error {
	return a.azCli.StartVM(ctx, instance)
}
