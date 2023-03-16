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
	controllerIDTagName = "garm-controller-id"
	poolIDTagName       = "garm-pool-id"
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
	return &azureProvider{
		cfg:          conf,
		creds:        creds,
		controllerID: controllerID,
	}, nil
}

type azureProvider struct {
	cfg          *config.Config
	creds        azcore.TokenCredential
	controllerID string
}

// CreateInstance creates a new compute instance in the provider.
func (a *azureProvider) CreateInstance(ctx context.Context, bootstrapParams params.BootstrapInstance) (params.Instance, error) {
	if bootstrapParams.OSArch != params.Amd64 {
		// x86_64 only for now. Azure does seem to support arm64, which we will look at at a later time.
		return params.Instance{}, fmt.Errorf("invalid architecture %s (supported: %s)", bootstrapParams.OSArch, params.Amd64)
	}

	// resourceTags, err := tagsFromBootstrapParams(bootstrapParams)
	// if err != nil {
	// 	return params.Instance{}, fmt.Errorf("failed to get tags: %w", err)
	// }

	// imgDetails, err := urnToImageDetails(bootstrapParams.Image)
	// if err != nil {
	// 	return params.Instance{}, fmt.Errorf("failed to get image details: %w", err)
	// }
	return params.Instance{}, nil
}

// Delete instance will delete the instance in a provider.
func (a *azureProvider) DeleteInstance(ctx context.Context, instance string) error {
	return nil
}

// GetInstance will return details about one instance.
func (a *azureProvider) GetInstance(ctx context.Context, instance string) (params.Instance, error) {
	return params.Instance{}, nil
}

// ListInstances will list all instances for a provider.
func (a *azureProvider) ListInstances(ctx context.Context, poolID string) ([]params.Instance, error) {
	return nil, nil
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
