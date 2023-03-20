package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/cloudbase/garm-provider-azure/userdata"
	"github.com/cloudbase/garm/params"
	"github.com/cloudbase/garm/util"
	"github.com/google/go-github/v48/github"
)

const (
	defaultAdminName          = "garm"
	defaultStorageAccountType = armcompute.StorageAccountTypesStandardLRS

	defaultDiskSizeGB int32 = 127
)

func newExtraSpecsFromBootstrapData(data params.BootstrapInstance) (*extraSpecs, error) {
	spec := &extraSpecs{}

	if len(data.ExtraSpecs) > 0 {
		if err := json.Unmarshal(data.ExtraSpecs, spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal extra specs: %w", err)
		}
	}
	spec.ensureValidExtraSpec()

	return spec, nil
}

type extraSpecs struct {
	AllocatePublicIP   bool                                      `json:"allocate_public_ip"`
	OpenInboundPorts   map[armnetwork.SecurityRuleProtocol][]int `json:"open_inbound_ports"`
	AdminUsername      string                                    `json:"admin_username"`
	StorageAccountType armcompute.StorageAccountTypes            `json:"storage_account_type"`
	DiskSizeGB         int32                                     `json:"disk_size_gb"`
}

func (e *extraSpecs) cleanInboundPorts() {
	if e.OpenInboundPorts != nil {
		tmpInbound := map[armnetwork.SecurityRuleProtocol][]int{}
		for proto, ports := range e.OpenInboundPorts {
			if proto != armnetwork.SecurityRuleProtocolTCP && proto != armnetwork.SecurityRuleProtocolUDP {
				continue
			}
			for _, port := range ports {
				if port < 1 && port > 65535 {
					continue
				}
				tmpInbound[proto] = append(tmpInbound[proto], port)
			}
		}
		e.OpenInboundPorts = tmpInbound
	}
}

func (e *extraSpecs) cleanStorageAccountType() {
	if e.StorageAccountType == "" {
		e.StorageAccountType = defaultStorageAccountType
		return
	}

	acctTypes := armcompute.PossibleStorageAccountTypesValues()
	for _, acctType := range acctTypes {
		if acctType == e.StorageAccountType {
			// Valid acct type. Return here.
			return
		}
	}
	e.StorageAccountType = defaultStorageAccountType
}

func (e *extraSpecs) ensureValidExtraSpec() {
	e.cleanInboundPorts()
	e.cleanStorageAccountType()
	if e.DiskSizeGB == 0 {
		e.DiskSizeGB = defaultDiskSizeGB
	}
	if e.AdminUsername == "" {
		e.AdminUsername = defaultAdminName
	}
}

func GetRunnerSpecFromBootstrapParams(data params.BootstrapInstance) (*runnerSpec, error) {
	tools, err := util.GetTools(data.OSType, data.OSArch, data.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to get tools: %s", err)
	}

	extraSpecs, err := newExtraSpecsFromBootstrapData(data)
	if err != nil {
		return nil, fmt.Errorf("error loading extra specs: %w", err)
	}

	spec := &runnerSpec{
		VMSize:             data.Flavor,
		AllocatePublicIP:   extraSpecs.AllocatePublicIP,
		OpenInboundPorts:   extraSpecs.OpenInboundPorts,
		AdminUsername:      extraSpecs.AdminUsername,
		StorageAccountType: extraSpecs.StorageAccountType,
		DiskSizeGB:         extraSpecs.DiskSizeGB,
		BootstrapParams:    data,
		Tools:              tools,
	}

	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("error validating spec: %w", err)
	}

	return spec, nil
}

type runnerSpec struct {
	VMSize             string
	AllocatePublicIP   bool
	AdminUsername      string
	StorageAccountType armcompute.StorageAccountTypes
	DiskSizeGB         int32
	OpenInboundPorts   map[armnetwork.SecurityRuleProtocol][]int
	BootstrapParams    params.BootstrapInstance
	Tools              github.RunnerApplicationDownload
	UseCloudInit       bool
}

func (r runnerSpec) Validate() error {
	if r.VMSize == "" {
		return fmt.Errorf("missing flavor")
	}

	if r.AdminUsername == "" {
		return fmt.Errorf("missing admin username")
	}
	if r.StorageAccountType == "" {
		return fmt.Errorf("missing storage account type")
	}

	if r.DiskSizeGB == 0 {
		return fmt.Errorf("invalid disk size")
	}

	if r.Tools.DownloadURL == nil {
		return fmt.Errorf("missing tools")
	}

	if r.BootstrapParams.Name == "" || r.BootstrapParams.OSType == "" || r.BootstrapParams.InstanceToken == "" {
		return fmt.Errorf("invalid bootstrap params")
	}

	return nil
}

func (r runnerSpec) ImageDetails() (imageDetails, error) {
	if r.BootstrapParams.Image == "" {
		return imageDetails{}, fmt.Errorf("no image specified in bootstrap params")
	}
	imgDetails, err := urnToImageDetails(r.BootstrapParams.Image)
	if err != nil {
		return imageDetails{}, fmt.Errorf("failed to get image details: %w", err)
	}
	return imgDetails, nil
}

func (r runnerSpec) ComposeUserData() ([]byte, error) {
	switch r.BootstrapParams.OSType {
	case params.Linux, params.Windows:
		udata, err := util.GetCloudConfig(r.BootstrapParams, r.Tools, r.BootstrapParams.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to generate userdata: %w", err)
		}
		return []byte(udata), nil
	}
	return nil, fmt.Errorf("unsupported OS type for cloud config: %s", r.BootstrapParams.OSType)
}

func (r runnerSpec) SecurityRules() []*armnetwork.SecurityRule {
	if len(r.OpenInboundPorts) == 0 {
		return nil
	}

	var ret []*armnetwork.SecurityRule
	for proto, ports := range r.OpenInboundPorts {
		for _, port := range ports {
			ret = append(ret, &armnetwork.SecurityRule{
				Name: to.Ptr(fmt.Sprintf("inbound_%s_%d", proto, port)),
				Properties: &armnetwork.SecurityRulePropertiesFormat{
					SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),
					SourcePortRange:          to.Ptr("*"),
					DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
					DestinationPortRange:     to.Ptr(strconv.Itoa(port)),
					Protocol:                 to.Ptr(proto),
					Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
					Priority:                 to.Ptr[int32](100),
					Description:              to.Ptr(fmt.Sprintf("open inbound %s port %d", proto, port)),
					Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				},
			})
		}
	}
	return ret
}

func (r runnerSpec) GetVMExtension(location, extName string) (*armcompute.VirtualMachineExtension, error) {
	switch r.BootstrapParams.OSType {
	case params.Windows:
		scriptCmd, err := userdata.GetWindowsRunScriptCommand(r.BootstrapParams.InstanceToken)
		if err != nil {
			return nil, fmt.Errorf("failed to get run script: %w", err)
		}

		asBytes, err := util.UTF16EncodedByteArrayFromString(string(scriptCmd))
		if err != nil {
			return nil, fmt.Errorf("failed to encode script cmd: %w", err)
		}

		asBase64 := base64.StdEncoding.EncodeToString(asBytes)
		ext := &armcompute.VirtualMachineExtension{
			Location: to.Ptr(location),
			Tags: map[string]*string{
				"displayName": to.Ptr(extName),
			},
			Type: to.Ptr("Microsoft.Compute/virtualMachines/extensions"),
			Name: to.Ptr(fmt.Sprintf("%s/%s", r.BootstrapParams.Name, extName)),
			Properties: &armcompute.VirtualMachineExtensionProperties{
				Publisher:          to.Ptr("Microsoft.Compute"),
				Type:               to.Ptr("CustomScriptExtension"),
				TypeHandlerVersion: to.Ptr("1.10"),
				ProtectedSettings: &map[string]interface{}{
					"commandToExecute": fmt.Sprintf("powershell.exe -NonInteractive -EncodedCommand %s", asBase64),
				},
			},
		}
		return ext, nil
	}
	return nil, nil
}

func (r runnerSpec) GetNewVMProperties(networkInterfaceID string) (*armcompute.VirtualMachineProperties, error) {
	imgDetails, err := r.ImageDetails()
	if err != nil {
		return nil, fmt.Errorf("failed to getimage details: %w", err)
	}
	password, err := util.GetRandomString(24)
	if err != nil {
		return nil, fmt.Errorf("failed to get random string: %w", err)
	}

	customData, err := r.ComposeUserData()
	if err != nil {
		return nil, fmt.Errorf("failed to compose userdata: %w", err)
	}

	if len(customData) == 0 {
		return nil, fmt.Errorf("failed to generate custom data")
	}

	asBase64 := base64.StdEncoding.EncodeToString(customData)

	if r.VMSize == "" {
		return nil, fmt.Errorf("missing vm size parameter")
	}

	properties := &armcompute.VirtualMachineProperties{
		StorageProfile: &armcompute.StorageProfile{
			ImageReference: &armcompute.ImageReference{
				Offer:     to.Ptr(imgDetails.Offer),
				Publisher: to.Ptr(imgDetails.Publisher),
				SKU:       to.Ptr(imgDetails.SKU),
				Version:   to.Ptr(imgDetails.Version),
			},
			OSDisk: &armcompute.OSDisk{
				Name:         to.Ptr(r.BootstrapParams.Name),
				CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
				Caching:      to.Ptr(armcompute.CachingTypesReadWrite),
				ManagedDisk: &armcompute.ManagedDiskParameters{
					StorageAccountType: &r.StorageAccountType,
				},
				DiskSizeGB: &r.DiskSizeGB,
			},
		},
		HardwareProfile: &armcompute.HardwareProfile{
			VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(r.VMSize)),
		},
		OSProfile: &armcompute.OSProfile{
			CustomData: &asBase64,
			// Windows computer names may not be longer than 15 characters.
			ComputerName:  to.Ptr(r.BootstrapParams.Name[:15]),
			AdminUsername: to.Ptr(r.AdminUsername),
			AdminPassword: &password,
		},
		NetworkProfile: &armcompute.NetworkProfile{
			NetworkInterfaces: []*armcompute.NetworkInterfaceReference{
				{
					ID: to.Ptr(networkInterfaceID),
				},
			},
		},
	}

	if r.BootstrapParams.OSType == params.Linux {
		properties.OSProfile.LinuxConfiguration = &armcompute.LinuxConfiguration{
			// password is a 24 random string that is never disclosed to anyone.
			DisablePasswordAuthentication: to.Ptr(false),
		}
	}
	return properties, nil
}
