package provider

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/cloudbase/garm-provider-azure/config"

	"github.com/cloudbase/garm/params"
	"github.com/cloudbase/garm/runner/providers/external/execution"
)

var _ execution.ExternalProvider = &azureProvider{}

const (
	controllerIDTagName = "garm_controller_id"
	poolIDTagName       = "garm_pool_id"
)

func NewAzureProvider(configPath, controllerID string) (execution.ExternalProvider, error) {
	conf, err := config.NewConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("error loading config: %w", err)
	}
	creds, err := conf.GetCredentials()
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	azCli, err := newAzCLI(conf)
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
	azCli        *azureCli
}

// CreateInstance creates a new compute instance in the provider.
func (a *azureProvider) CreateInstance(ctx context.Context, bootstrapParams params.BootstrapInstance) (params.Instance, error) {
	if bootstrapParams.OSArch != params.Amd64 {
		// x86_64 only for now. Azure does seem to support arm64, which we will look at at a later time.
		return params.Instance{}, fmt.Errorf("invalid architecture %s (supported: %s)", bootstrapParams.OSArch, params.Amd64)
	}

	resourceTags, err := tagsFromBootstrapParams(bootstrapParams)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to get tags: %w", err)
	}

	spec, err := GetRunnerSpecFromBootstrapParams(bootstrapParams)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to generate spec: %w", err)
	}

	_, err = a.azCli.createResourceGroup(ctx, spec.BootstrapParams.Name, resourceTags)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create resource group: %w", err)
	}

	defer func() {
		if err != nil {
			a.azCli.deleteResourceGroup(ctx, spec.BootstrapParams.Name)
		}
	}()

	_, err = a.azCli.createVirtualNetwork(ctx, spec.BootstrapParams.Name, "10.10.0.0/16")
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create virtual network: %w", err)
	}

	subnet, err := a.azCli.createSubnet(ctx, spec.BootstrapParams.Name, "10.10.1.0/24")
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create subnet: %w", err)
	}

	var pubIP string
	if spec.AllocatePublicIP {
		publicIP, err := a.azCli.createPublicIP(ctx, spec.BootstrapParams.Name)
		if err != nil {
			return params.Instance{}, fmt.Errorf("failed to create public IP: %w", err)
		}
		pubIP = *publicIP.ID
	}

	nsg, err := a.azCli.createNetworkSecurityGroup(ctx, spec.BootstrapParams.Name, spec)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create network security group: %w", err)
	}

	nic, err := a.azCli.createNetWorkInterface(ctx, spec.BootstrapParams.Name, *subnet.ID, *nsg.ID, pubIP)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create NIC: %w", err)
	}

	vm, err := a.azCli.createVirtualMachine(ctx, spec, *nic.ID, resourceTags)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to create VM: %w", err)
	}

	if vm == nil {
		return params.Instance{}, fmt.Errorf("failed to get VM details")
	}
	vmParams, err := azureInstanceToParamsInstance(*vm)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to get vm details: %w", err)
	}
	return vmParams, nil
}

// Delete instance will delete the instance in a provider.
func (a *azureProvider) DeleteInstance(ctx context.Context, instance string) error {
	return nil
}

// GetInstance will return details about one instance.
func (a *azureProvider) GetInstance(ctx context.Context, instance string) (params.Instance, error) {
	vm, err := a.azCli.getInstance(ctx, instance, instance)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to get VM details: %w", err)
	}
	details, err := azureInstanceToParamsInstance(vm)
	if err != nil {
		return params.Instance{}, fmt.Errorf("failed to convert VM details: %w", err)
	}
	return details, nil
}

// ListInstances will list all instances for a provider.
func (a *azureProvider) ListInstances(ctx context.Context, poolID string) ([]params.Instance, error) {
	instances, err := a.azCli.listVirtualMachines(ctx, poolID)
	if err != nil {
		return nil, fmt.Errorf("failed to list instances: %w", err)
	}

	if instances == nil {
		return nil, fmt.Errorf("invalid instances response")
	}
	resp := make([]params.Instance, len(instances))
	for idx, val := range instances {
		if val == nil {
			return nil, fmt.Errorf("nil vm object in response")
		}
		details, err := azureInstanceToParamsInstance(*val)
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
	return nil
}

// Start boots up an instance.
func (a *azureProvider) Start(ctx context.Context, instance string) error {
	return nil
}
