package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/cloudbase/garm-provider-azure/config"
	"github.com/cloudbase/garm-provider-azure/internal/client"
	"github.com/cloudbase/garm-provider-azure/internal/spec"
	"github.com/cloudbase/garm-provider-azure/internal/util"

	"github.com/cloudbase/garm/params"
	"github.com/cloudbase/garm/runner/providers/external/execution"
)

var _ execution.ExternalProvider = &azureProvider{}

func NewAzureProvider(configPath, controllerID string) (execution.ExternalProvider, error) {
	conf, err := config.NewConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	creds, err := conf.Credentials.GetCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	azCli, err := client.NewAzCLI(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to get azure CLI: %w", err)
	}
	return &azureProvider{
		cfg:          conf,
		creds:        creds,
		controllerID: controllerID,
		azCli:        azCli,
	}, nil
}

type azureProvider struct {
	cfg          *config.Config
	creds        azcore.TokenCredential
	controllerID string
	azCli        *client.AzureCli
}

// CreateInstance creates a new compute instance in the provider.
func (a *azureProvider) CreateInstance(ctx context.Context, bootstrapParams params.BootstrapInstance) (params.Instance, error) {
	if bootstrapParams.OSArch != params.Amd64 {
		// x86_64 only for now. Azure does seem to support arm64, which we will look at at a later time.
		return params.Instance{}, fmt.Errorf("invalid architecture %s (supported: %s)", bootstrapParams.OSArch, params.Amd64)
	}

	spec, err := spec.GetRunnerSpecFromBootstrapParams(bootstrapParams, a.controllerID)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to generate spec: %w", err)
	}

	imgDetails, err := spec.ImageDetails()
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to get image details: %w", err)
	}
	_, err = a.azCli.CreateResourceGroup(ctx, spec.BootstrapParams.Name, spec.Tags)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create resource group: %w", err)
	}

	defer func() {
		if err != nil {
			a.azCli.DeleteResourceGroup(ctx, spec.BootstrapParams.Name, true) //nolint
		}
	}()

	_, err = a.azCli.CreateVirtualNetwork(ctx, spec.BootstrapParams.Name, "10.10.0.0/16")
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create virtual network: %w", err)
	}

	subnet, err := a.azCli.CreateSubnet(ctx, spec.BootstrapParams.Name, "10.10.1.0/24")
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create subnet: %w", err)
	}

	var pubIPID string
	var pubIP string
	if spec.AllocatePublicIP {
		publicIP, err := a.azCli.CreatePublicIP(ctx, spec.BootstrapParams.Name)
		if err != nil {
			return params.Instance{}, fmt.Errorf("failed to create public IP: %w", err)
		}
		if publicIP.Properties != nil && publicIP.Properties.IPAddress != nil {
			pubIP = *publicIP.Properties.IPAddress
		}
		pubIPID = *publicIP.ID
	}

	nsg, err := a.azCli.CreateNetworkSecurityGroup(ctx, spec.BootstrapParams.Name, spec)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create network security group: %w", err)
	}

	nic, err := a.azCli.CreateNetWorkInterface(ctx, spec.BootstrapParams.Name, *subnet.ID, *nsg.ID, pubIPID)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create NIC: %w", err)
	}

	if err := a.azCli.CreateVirtualMachine(ctx, spec, *nic.ID, spec.Tags); err != nil {
		return params.Instance{}, fmt.Errorf("failed to create VM: %w", err)
	}

	// We're lying here. It takes longer for the client to finish polling than for the VM to
	// start running the userdata. Just return that the instance is running once the request
	// to create it goes through.
	instance := params.Instance{
		ProviderID: spec.BootstrapParams.Name,
		Name:       spec.BootstrapParams.Name,
		OSType:     spec.BootstrapParams.OSType,
		OSArch:     spec.BootstrapParams.OSArch,
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

// Delete instance will delete the instance in a provider.
func (a *azureProvider) DeleteInstance(ctx context.Context, instance string) error {
	err := a.azCli.DeleteResourceGroup(ctx, instance, true)
	if err != nil {
		return fmt.Errorf("failed to delete instance: %w", err)
	}
	return nil
}

// GetInstance will return details about one instance.
func (a *azureProvider) GetInstance(ctx context.Context, instance string) (params.Instance, error) {
	vm, err := a.azCli.GetInstance(ctx, instance, instance)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to get VM details: %w", err)
	}
	details, err := util.AzureInstanceToParamsInstance(vm)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to convert VM details: %w", err)
	}
	return details, nil
}

// ListInstances will list all instances for a provider.
func (a *azureProvider) ListInstances(ctx context.Context, poolID string) ([]params.Instance, error) {
	instances, err := a.azCli.ListVirtualMachines(ctx, poolID)
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}

	if instances == nil {
		return []params.Instance{}, nil
	}

	resp := make([]params.Instance, len(instances))
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
	return a.azCli.DealocateVM(ctx, instance, instance)
}

// Start boots up an instance.
func (a *azureProvider) Start(ctx context.Context, instance string) error {
	return a.azCli.StartVM(ctx, instance)
}
