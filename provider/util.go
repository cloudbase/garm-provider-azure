package provider

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"

	"github.com/cloudbase/garm/params"
	"github.com/cloudbase/garm/runner/providers/common"
)

var (
	powerStateMap = map[string]string{
		"PowerState/deallocated":  "stopped",
		"PowerState/deallocating": "stopped",
		"PowerState/running":      "running",
		"PowerState/starting":     "pending_create",
		"PowerState/stopped":      "stopped",
		"PowerState/stopping":     "stopped",
		"PowerState/unknown":      "unknown",
	}
)

func tagsFromBootstrapParams(bootstrapParams params.BootstrapInstance) (map[string]*string, error) {
	imageDetails, err := urnToImageDetails(bootstrapParams.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image: %w", err)
	}

	// TAGS="garm_controller_id=${GARM_CONTROLLER_ID} garm_pool_id=${GARM_POOL_ID} os_type=${OS_TYPE} os_name=${OS_NAME} os_version=${OS_VERSION} os_arch=${ARCH}"
	ret := map[string]*string{
		"os_arch":     to.Ptr(string(bootstrapParams.OSArch)),
		"os_version":  to.Ptr(imageDetails.Version),
		"os_name":     to.Ptr(imageDetails.SKU),
		poolIDTagName: to.Ptr(bootstrapParams.PoolID),
	}

	return ret, nil
}

type imageDetails struct {
	Offer     string
	Publisher string
	SKU       string
	Version   string
}

func urnToImageDetails(urn string) (imageDetails, error) {
	// MicrosoftWindowsServer:WindowsServer:2022-Datacenter:latest
	fields := strings.Split(urn, ":")
	if len(fields) != 4 {
		return imageDetails{}, fmt.Errorf("invalid image URN: %s", urn)
	}

	return imageDetails{
		Publisher: fields[0],
		Offer:     fields[1],
		SKU:       fields[2],
		Version:   fields[3],
	}, nil
}

func azurePowerStateToGarmPowerState(vm armcompute.VirtualMachine) string {
	if vm.Properties == nil || vm.Properties.InstanceView == nil || vm.Properties.InstanceView.Statuses == nil {
		return "unknown"
	}

	for _, val := range vm.Properties.InstanceView.Statuses {
		if val.Code != nil {
			code, ok := powerStateMap[*val.Code]
			if ok {
				return code
			}
		}
	}

	return "unknown"
}

func azureInstanceToParamsInstance(vm armcompute.VirtualMachine) (params.Instance, error) {
	if vm.Name == nil {
		return params.Instance{}, fmt.Errorf("missing VM name")
	}
	os_type, ok := vm.Tags["os_type"]
	if !ok {
		return params.Instance{}, fmt.Errorf("missing os_type tag in VM")
	}
	os_arch, ok := vm.Tags["os_arch"]
	if !ok {
		return params.Instance{}, fmt.Errorf("missing os_arch tag in VM")
	}
	os_version, ok := vm.Tags["os_version"]
	if !ok {
		return params.Instance{}, fmt.Errorf("missing os_version tag in VM")
	}
	os_name, ok := vm.Tags["os_name"]
	if !ok {
		return params.Instance{}, fmt.Errorf("missing os_name tag in VM")
	}
	return params.Instance{
		ProviderID: *vm.Name,
		Name:       *vm.Name,
		OSType:     params.OSType(*os_type),
		OSArch:     params.OSArch(*os_arch),
		OSName:     *os_name,
		OSVersion:  *os_version,
		Status:     common.InstanceStatus(azurePowerStateToGarmPowerState(vm)),
	}, nil
}
