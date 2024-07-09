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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v5"
	"github.com/cloudbase/garm-provider-common/cloudconfig"
	appdefaults "github.com/cloudbase/garm-provider-common/defaults"
	"github.com/cloudbase/garm-provider-common/params"
	"github.com/cloudbase/garm-provider-common/util"
	"github.com/xeipuuv/gojsonschema"
	"golang.org/x/crypto/ssh"

	"github.com/cloudbase/garm-provider-azure/config"
	providerUtil "github.com/cloudbase/garm-provider-azure/internal/util"
)

const (
	defaultStorageAccountType = armcompute.StorageAccountTypesStandardLRS
	windowsRunScriptTemplate  = "try { gc -Raw C:/AzureData/CustomData.bin | sc /run.ps1; /run.ps1 } finally { rm -Force -ErrorAction SilentlyContinue /run.ps1 }"

	defaultDiskSizeGB             int32  = 127
	defaultVirtualNetworkCIDR     string = "10.10.0.0/16"
	defaultEphemeralDiskPlacement string = "ResourceDisk"
	jsonSchema                    string = `
		{
			"$schema": "http://cloudbase.it/garm-provider-azure/schemas/extra_specs#",
			"type": "object",
			"description": "Schema defining supported extra specs for the Garm Azure Provider",
			"properties": {
				"allocate_public_ip": {
					"type": "boolean",
					"description": "Allocate a public IP to the VM."
				},
				"confidential": {
					"type": "boolean",
					"description": "The selected virtual machine size is confidential."
				},
				"use_ephemeral_storage": {
					"type": "boolean",
					"description": "Use ephemeral storage for the VM."
				},
				"use_accelerated_networking": {
					"type": "boolean",
					"description": "Use accelerated networking for the VM."
				},
				"open_inbound_ports": {
					"type": "object",
					"description": "A map of protocol to list of inbound ports to open.",
					"properties": {
						"Tcp": {
							"type": "array",
							"description": "List of ports to open.",
							"items": {
								"type": "integer",
								"minimum": 1,
								"maximum": 65535
							}
						},
						"Udp": {
							"type": "array",
							"description": "List of ports to open.",
							"items": {
								"type": "integer",
								"minimum": 1,
								"maximum": 65535
							}
						}
					}
				},
				"storage_account_type": {
					"type": "string",
					"description": "Azure storage account type. Default is Standard_LRS."
				},
				"virtual_network_cidr": {
					"type": "string",
					"description": "The CIDR for the virtual network."
				},
				"disk_size_gb": {
					"type": "integer",
					"description": "The size of the root disk in GB. Default is 127 GB."
				},
				"extra_tags": {
					"type": "object",
					"description": "Extra tags that will get added to all VMs spawned in a pool."
				},
				"ssh_public_keys": {
					"type": "array",
					"description": "SSH public keys to add to the admin user on Linux runners.",
					"items": {
						"type": "string"
					}
				},
				"vnet_subnet_id": {
					"type": "string",
					"description": "The ID of the subnet to use for the VM. Must be in the same region as the VM. This is required if disable_isolated_networks is set to true, otherwise it is ignored."
				},
				"disable_updates": {
					"type": "boolean",
					"description": "Disable automatic updates on the VM."
				},
				"enable_boot_debug": {
					"type": "boolean",
					"description": "Enable boot debug on the VM."
				},
				"extra_packages": {
					"type": "array",
					"description": "Extra packages to install on the VM.",
					"items": {
						"type": "string"
					}
				},
				"runner_install_template": {
					"type": "string",
					"description": "This option can be used to override the default runner install template. If used, the caller is responsible for the correctness of the template as well as the suitability of the template for the target OS. Use the extra_context extra spec if your template has variables in it that need to be expanded."
				},
				"extra_context": {
					"type": "object",
					"description": "Extra context that will be passed to the runner_install_template.",
					"additionalProperties": {
						"type": "string"
					}
				},
				"pre_install_scripts": {
					"type": "object",
					"description": "A map of pre-install scripts that will be run before the runner install script. These will run as root and can be used to prep a generic image before we attempt to install the runner. The key of the map is the name of the script as it will be written to disk. The value is a byte array with the contents of the script."
				},
				"disable_isolated_networks": {
					"type": "boolean",
					"description": "Disable network isolation for the VM."
				}
			},
			"additionalProperties": false
		}
	`
)

func jsonSchemaValidation(schema json.RawMessage) error {
	schemaLoader := gojsonschema.NewStringLoader(jsonSchema)
	extraSpecsLoader := gojsonschema.NewBytesLoader(schema)
	result, err := gojsonschema.Validate(schemaLoader, extraSpecsLoader)
	if err != nil {
		return fmt.Errorf("failed to validate schema: %w", err)
	}
	if !result.Valid() {
		return fmt.Errorf("schema validation failed: %s", result.Errors())
	}
	return nil
}

type VMSizeEphemeralDiskSizeLimits struct {
	ResourceDiskSizeGB int32
	CacheDiskSizeGB    int32
}

func (v VMSizeEphemeralDiskSizeLimits) EphemeralSettings() (int32, *armcompute.DiffDiskPlacement, error) {
	if v.CacheDiskSizeGB > 0 {
		return v.CacheDiskSizeGB, to.Ptr(armcompute.DiffDiskPlacementCacheDisk), nil
	}
	if v.ResourceDiskSizeGB > 0 {
		return v.ResourceDiskSizeGB, to.Ptr(armcompute.DiffDiskPlacementResourceDisk), nil
	}
	return 0, nil, fmt.Errorf("invalid ephemeral disk size limits")
}

func newExtraSpecsFromBootstrapData(data params.BootstrapInstance) (*extraSpecs, error) {
	spec := &extraSpecs{}

	if err := jsonSchemaValidation(data.ExtraSpecs); err != nil {
		return nil, fmt.Errorf("failed to validate extra specs: %w", err)
	}

	if len(data.ExtraSpecs) > 0 {
		if err := json.Unmarshal(data.ExtraSpecs, spec); err != nil {
			return nil, fmt.Errorf("failed to unmarshal extra specs: %w", err)
		}
	}
	spec.ensureValidExtraSpec()

	return spec, nil
}

type extraSpecs struct {
	AllocatePublicIP         bool                                      `json:"allocate_public_ip"`
	OpenInboundPorts         map[armnetwork.SecurityRuleProtocol][]int `json:"open_inbound_ports"`
	StorageAccountType       armcompute.StorageAccountTypes            `json:"storage_account_type"`
	DiskSizeGB               int32                                     `json:"disk_size_gb"`
	ExtraTags                map[string]string                         `json:"extra_tags"`
	SSHPublicKeys            []string                                  `json:"ssh_public_keys"`
	Confidential             bool                                      `json:"confidential"`
	UseEphemeralStorage      *bool                                     `json:"use_ephemeral_storage"`
	VirtualNetworkCIDR       string                                    `json:"virtual_network_cidr"`
	UseAcceleratedNetworking *bool                                     `json:"use_accelerated_networking"`
	VnetSubnetID             string                                    `json:"vnet_subnet_id"`
	DisableIsolatedNetworks  *bool                                     `json:"disable_isolated_networks"`
	DisableUpdates           *bool                                     `json:"disable_updates"`
	EnableBootDebug          *bool                                     `json:"enable_boot_debug"`
	ExtraPackages            []string                                  `json:"extra_packages"`
}

func (e *extraSpecs) cleanInboundPorts() {
	if e.OpenInboundPorts == nil {
		e.OpenInboundPorts = map[armnetwork.SecurityRuleProtocol][]int{}
	}

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

	if e.ExtraTags == nil {
		e.ExtraTags = map[string]string{}
	}
}

func GetRunnerSpecFromBootstrapParams(data params.BootstrapInstance, controllerID string, cfg *config.Config) (*RunnerSpec, error) {
	if cfg == nil {
		return nil, fmt.Errorf("missing config")
	}

	tools, err := util.GetTools(data.OSType, data.OSArch, data.Tools)
	if err != nil {
		return nil, fmt.Errorf("failed to get tools: %s", err)
	}

	extraSpecs, err := newExtraSpecsFromBootstrapData(data)
	if err != nil {
		return nil, fmt.Errorf("error loading extra specs: %w", err)
	}

	// VirtualNetworkCIDR will be set to default, config value or extraSpecs value,
	// in that order of precedence.
	virtualNetworkCIDR := defaultVirtualNetworkCIDR
	if cfg.VirtualNetworkCIDR != "" {
		virtualNetworkCIDR = cfg.VirtualNetworkCIDR
	}
	if extraSpecs.VirtualNetworkCIDR != "" {
		if _, _, err := net.ParseCIDR(extraSpecs.VirtualNetworkCIDR); err != nil {
			return nil, fmt.Errorf("invalid virtual network CIDR: %w", err)
		}
		virtualNetworkCIDR = extraSpecs.VirtualNetworkCIDR
	}

	tags, err := providerUtil.TagsFromBootstrapParams(data, controllerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tags: %w", err)
	}

	for name, val := range extraSpecs.ExtraTags {
		tags[name] = to.Ptr(val)
	}

	spec := &RunnerSpec{
		VMSize:                   data.Flavor,
		AllocatePublicIP:         extraSpecs.AllocatePublicIP,
		OpenInboundPorts:         extraSpecs.OpenInboundPorts,
		AdminUsername:            appdefaults.DefaultUser,
		StorageAccountType:       extraSpecs.StorageAccountType,
		DiskSizeGB:               extraSpecs.DiskSizeGB,
		SSHPublicKeys:            extraSpecs.SSHPublicKeys,
		BootstrapParams:          data,
		Tools:                    tools,
		Tags:                     tags,
		Confidential:             extraSpecs.Confidential,
		UseEphemeralStorage:      cfg.UseEphemeralStorage,
		VirtualNetworkCIDR:       virtualNetworkCIDR,
		UseAcceleratedNetworking: cfg.UseAcceleratedNetworking,
		VnetSubnetID:             cfg.VnetSubnetID,
		DisableIsolatedNetworks:  cfg.DisableIsolatedNetworks,
		ExtraPackages:            extraSpecs.ExtraPackages,
	}

	if extraSpecs.UseEphemeralStorage != nil {
		spec.UseEphemeralStorage = *extraSpecs.UseEphemeralStorage
	}

	if extraSpecs.UseAcceleratedNetworking != nil {
		spec.UseAcceleratedNetworking = *extraSpecs.UseAcceleratedNetworking
	}

	if extraSpecs.DisableUpdates != nil {
		spec.DisableUpdates = *extraSpecs.DisableUpdates
	}

	if extraSpecs.EnableBootDebug != nil {
		spec.EnableBootDebug = *extraSpecs.EnableBootDebug
	}

	if extraSpecs.DisableIsolatedNetworks != nil {
		spec.DisableIsolatedNetworks = *extraSpecs.DisableIsolatedNetworks
	}

	if extraSpecs.VnetSubnetID != "" && spec.DisableIsolatedNetworks {
		spec.VnetSubnetID = extraSpecs.VnetSubnetID
	}

	if !spec.UseEphemeralStorage && spec.DiskSizeGB == 0 {
		spec.DiskSizeGB = defaultDiskSizeGB
	}

	if err := spec.Validate(); err != nil {
		return nil, fmt.Errorf("error validating spec: %w", err)
	}

	return spec, nil
}

type RunnerSpec struct {
	VMSize                   string
	AllocatePublicIP         bool
	AdminUsername            string
	StorageAccountType       armcompute.StorageAccountTypes
	DiskSizeGB               int32
	OpenInboundPorts         map[armnetwork.SecurityRuleProtocol][]int
	BootstrapParams          params.BootstrapInstance
	Tools                    params.RunnerApplicationDownload
	Tags                     map[string]*string
	SSHPublicKeys            []string
	Confidential             bool
	UseEphemeralStorage      bool
	VirtualNetworkCIDR       string
	UseAcceleratedNetworking bool
	VnetSubnetID             string
	DisableIsolatedNetworks  bool
	DisableUpdates           bool
	ExtraPackages            []string
	EnableBootDebug          bool
}

func (r RunnerSpec) Validate() error {
	if r.VMSize == "" {
		return fmt.Errorf("missing flavor")
	}

	if r.AdminUsername == "" {
		return fmt.Errorf("missing admin username")
	}
	if r.StorageAccountType == "" {
		return fmt.Errorf("missing storage account type")
	}

	if r.DiskSizeGB == 0 && !r.UseEphemeralStorage {
		return fmt.Errorf("invalid disk size")
	}

	if r.Tools.DownloadURL == nil {
		return fmt.Errorf("missing tools")
	}

	if r.BootstrapParams.Name == "" || r.BootstrapParams.OSType == "" || r.BootstrapParams.InstanceToken == "" {
		return fmt.Errorf("invalid bootstrap params")
	}

	if err := config.ValidateVnetSubnet(r.VnetSubnetID); err != nil {
		return fmt.Errorf("invalid vnet subnet id: %w", err)
	}

	if len(r.SSHPublicKeys) > 0 {
		for _, key := range r.SSHPublicKeys {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
				return fmt.Errorf("failed to validate public key %s", key)
			}
		}
	}

	return nil
}

func (r RunnerSpec) ImageDetails() (providerUtil.ImageDetails, error) {
	if r.BootstrapParams.Image == "" {
		return providerUtil.ImageDetails{}, fmt.Errorf("no image specified in bootstrap params")
	}

	imgDetails, err := providerUtil.URNToImageDetails(r.BootstrapParams.Image)
	if err != nil {
		return providerUtil.ImageDetails{}, fmt.Errorf("failed to get image details: %w", err)
	}
	return imgDetails, nil
}

func (r RunnerSpec) ComposeUserData() ([]byte, error) {
	bootstrapParams := r.BootstrapParams
	bootstrapParams.UserDataOptions.DisableUpdatesOnBoot = r.DisableUpdates
	bootstrapParams.UserDataOptions.ExtraPackages = r.ExtraPackages
	bootstrapParams.UserDataOptions.EnableBootDebug = r.EnableBootDebug
	switch r.BootstrapParams.OSType {
	case params.Linux, params.Windows:
		udata, err := cloudconfig.GetCloudConfig(bootstrapParams, r.Tools, bootstrapParams.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to generate userdata: %w", err)
		}
		return []byte(udata), nil
	}
	return nil, fmt.Errorf("unsupported OS type for cloud config: %s", bootstrapParams.OSType)
}

func (r RunnerSpec) SecurityRules() []*armnetwork.SecurityRule {
	if len(r.OpenInboundPorts) == 0 {
		return nil
	}

	var ret []*armnetwork.SecurityRule
	secGroupPrio := 200
	for proto, ports := range r.OpenInboundPorts {
		for idx, port := range ports {
			ret = append(ret, &armnetwork.SecurityRule{
				Name: to.Ptr(fmt.Sprintf("inbound_%s_%d", proto, port)),
				Properties: &armnetwork.SecurityRulePropertiesFormat{
					SourceAddressPrefix:      to.Ptr("0.0.0.0/0"),
					SourcePortRange:          to.Ptr("*"),
					DestinationAddressPrefix: to.Ptr("0.0.0.0/0"),
					DestinationPortRange:     to.Ptr(strconv.Itoa(port)),
					Protocol:                 to.Ptr(proto),
					Access:                   to.Ptr(armnetwork.SecurityRuleAccessAllow),
					Priority:                 to.Ptr(int32(secGroupPrio + idx)),
					Description:              to.Ptr(fmt.Sprintf("open inbound %s port %d", proto, port)),
					Direction:                to.Ptr(armnetwork.SecurityRuleDirectionInbound),
				},
			})
		}
	}
	return ret
}

func (r RunnerSpec) GetVMExtension(location, extName string) (*armcompute.VirtualMachineExtension, error) {
	switch r.BootstrapParams.OSType {
	case params.Windows:
		asBytes, err := util.UTF16EncodedByteArrayFromString(windowsRunScriptTemplate)
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

func (r RunnerSpec) ephemeralDiskSettings(placement *armcompute.DiffDiskPlacement) *armcompute.DiffDiskSettings {
	if !r.UseEphemeralStorage {
		return nil
	}

	return &armcompute.DiffDiskSettings{
		Option:    to.Ptr(armcompute.DiffDiskOptionsLocal),
		Placement: placement,
	}
}

func (r RunnerSpec) managedDiskSettings() *armcompute.ManagedDiskParameters {
	if r.UseEphemeralStorage {
		return nil
	}
	params := &armcompute.ManagedDiskParameters{
		StorageAccountType: &r.StorageAccountType,
	}

	if r.Confidential {
		params.SecurityProfile = &armcompute.VMDiskSecurityProfile{
			SecurityEncryptionType: to.Ptr(armcompute.SecurityEncryptionTypesVMGuestStateOnly),
		}
	}
	return params
}

func (r RunnerSpec) securityProfile() *armcompute.SecurityProfile {
	// There are limitations based on OS, region and VM size. Too many variables
	// to sanely permit confidential VMs with ephemeral storage.
	if !r.Confidential || r.UseEphemeralStorage {
		return nil
	}
	securityProfile := &armcompute.SecurityProfile{
		SecurityType: to.Ptr(armcompute.SecurityTypesConfidentialVM),
		UefiSettings: &armcompute.UefiSettings{
			SecureBootEnabled: to.Ptr(true),
			VTpmEnabled:       to.Ptr(true),
		},
	}

	return securityProfile
}

func (r RunnerSpec) GetNewVMProperties(networkInterfaceID string, sizeSpec VMSizeEphemeralDiskSizeLimits) (*armcompute.VirtualMachineProperties, error) {
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

	managedDiskParams := r.managedDiskSettings()
	securityProfile := r.securityProfile()
	cacheType := to.Ptr(armcompute.CachingTypesReadWrite)
	diskSize := r.DiskSizeGB
	var diffSettings *armcompute.DiffDiskSettings

	if r.UseEphemeralStorage {
		size, placement, err := sizeSpec.EphemeralSettings()
		if err != nil {
			return nil, fmt.Errorf("failed to get ephemeral settings: %w", err)
		}
		diffSettings = r.ephemeralDiskSettings(placement)
		cacheType = to.Ptr(armcompute.CachingTypesReadOnly)

		if diskSize == 0 || diskSize >= size {
			diskSize = size
			// If confidential VMs are used with ephemeral storage, 1 GB is reserved.
			// See: https://learn.microsoft.com/en-us/azure/virtual-machines/ephemeral-os-disks#confidential-vms-using-ephemeral-os-disks
			// However, we disable confidential VMs for now, when ephemeral storage is used. We'll leave this recalculation of available
			// space, in case we enable it in the future.
			if r.Confidential {
				diskSize = diskSize - 1
			}
		}
	}

	imageReference := &armcompute.ImageReference{}

	if imgDetails.ID != "" {
		if imgDetails.IsCommunity {
			imageReference.CommunityGalleryImageID = to.Ptr(imgDetails.ID)
		} else {
			imageReference.ID = to.Ptr(imgDetails.ID)
		}
	} else {
		imageReference.Offer = to.Ptr(imgDetails.Offer)
		imageReference.Publisher = to.Ptr(imgDetails.Publisher)
		imageReference.SKU = to.Ptr(imgDetails.SKU)
		imageReference.Version = to.Ptr(imgDetails.Version)
	}

	properties := &armcompute.VirtualMachineProperties{
		StorageProfile: &armcompute.StorageProfile{
			ImageReference: imageReference,
			OSDisk: &armcompute.OSDisk{
				Name:             to.Ptr(r.BootstrapParams.Name),
				CreateOption:     to.Ptr(armcompute.DiskCreateOptionTypesFromImage),
				Caching:          cacheType,
				ManagedDisk:      managedDiskParams,
				DiffDiskSettings: diffSettings,
				DiskSizeGB:       &diskSize,
			},
		},
		HardwareProfile: &armcompute.HardwareProfile{
			VMSize: to.Ptr(armcompute.VirtualMachineSizeTypes(r.VMSize)),
		},
		OSProfile: &armcompute.OSProfile{
			CustomData: &asBase64,
			// Windows computer names may not be longer than 15 characters.
			ComputerName:  to.Ptr(r.BootstrapParams.Name[:min(len(r.BootstrapParams.Name), 15)]),
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
		SecurityProfile: securityProfile,
	}

	if r.BootstrapParams.OSType == params.Linux {
		// Linux computer names can be up to 63 characters long.
		properties.OSProfile.ComputerName = to.Ptr(r.BootstrapParams.Name[:min(len(r.BootstrapParams.Name), 63)])

		pubKeys := []*armcompute.SSHPublicKey{}
		fakeKey, err := providerUtil.GenerateFakeKey()
		if err == nil {
			pubKeys = append(pubKeys, &armcompute.SSHPublicKey{
				KeyData: to.Ptr(fakeKey),
				Path:    to.Ptr(path.Join("/home", appdefaults.DefaultUser, ".ssh/authorized_keys")),
			})
		}

		passwordAuth := false
		if len(r.SSHPublicKeys) > 0 {
			for _, pubKey := range r.SSHPublicKeys {
				pubKeys = append(pubKeys, &armcompute.SSHPublicKey{
					KeyData: to.Ptr(pubKey),
					Path:    to.Ptr(path.Join("/home", appdefaults.DefaultUser, ".ssh/authorized_keys")),
				})
			}
		}

		if len(pubKeys) == 0 {
			// last ditch effort. Enable password auth if we couldn't generate a fake
			// public key, and no keys were added in extra_specs.
			// Otherwise azure complains.
			passwordAuth = true
		}

		properties.OSProfile.LinuxConfiguration = &armcompute.LinuxConfiguration{
			// password is a 24 random string that is never disclosed to anyone.
			DisablePasswordAuthentication: to.Ptr(passwordAuth),
			SSH: &armcompute.SSHConfiguration{
				PublicKeys: pubKeys,
			},
		}
	}
	return properties, nil
}
