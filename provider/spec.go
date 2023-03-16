package provider

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/cloudbase/garm/params"
	"github.com/cloudbase/garm/util"
	"github.com/google/go-github/v48/github"
)

type OSPlatformType string

const (
	defaultAdminName          = "garm"
	defaultStorageAccountType = armcompute.StorageAccountTypesStandardLRS

	OSWindows         OSPlatformType = "windows"
	OSLinux           OSPlatformType = "linux"
	defaultDiskSizeGB int32          = 127
)

func newExtraSpecsFromBootstrapData(data params.BootstrapInstance) extraSpecs {
	var spec extraSpecs
	if err := json.Unmarshal(data.ExtraSpecs, &spec); err != nil {
		return extraSpecs{
			AdminUsername:      defaultAdminName,
			StorageAccountType: defaultStorageAccountType,
		}
	}
	spec.ensureValidExtraSpec()
	return spec
}

type extraSpecs struct {
	AllocatePublicIP   bool                                      `json:"allocate_public_ip"`
	OpenInboundPorts   map[armnetwork.SecurityRuleProtocol][]int `json:"open_inbound_ports"`
	AdminUsername      string                                    `json:"admin_username"`
	StorageAccountType armcompute.StorageAccountTypes            `json:"storage_account_type"`
	DiskSizeGB         int32                                     `json:"disk_size_gb"`
	UseCloudInit       bool                                      `json:"use_cloud_init"`
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

//	type BootstrapInstance struct {
//	    Name  string                              `json:"name"`
//	    Tools []*github.RunnerApplicationDownload `json:"tools"`
//	    // RepoURL is the URL the github runner agent needs to configure itself.
//	    RepoURL string `json:"repo_url"`
//	    // CallbackUrl is the URL where the instance can send a post, signaling
//	    // progress or status.
//	    CallbackURL string `json:"callback-url"`
//	    // MetadataURL is the URL where instances can fetch information needed to set themselves up.
//	    MetadataURL string `json:"metadata-url"`
//	    // InstanceToken is the token that needs to be set by the instance in the headers
//	    // in order to send updated back to the garm via CallbackURL.
//	    InstanceToken string `json:"instance-token"`
//	    // SSHKeys are the ssh public keys we may want to inject inside the runners, if the
//	    // provider supports it.
//	    SSHKeys []string `json:"ssh-keys"`
//	    // ExtraSpecs is an opaque raw json that gets sent to the provider
//	    // as part of the bootstrap params for instances. It can contain
//	    // any kind of data needed by providers. The contents of this field means
//	    // nothing to garm itself. We don't act on the information in this field at
//	    // all. We only validate that it's a proper json.
//
//	    ExtraSpecs json.RawMessage `json:"extra_specs,omitempty"`
//	    CACertBundle []byte `json:"ca-cert-bundle"`
//		    OSArch OSArch   `json:"arch"`
//		    Flavor string   `json:"flavor"`
//		    Image  string   `json:"image"`
//		    Labels []string `json:"labels"`
//		    PoolID string   `json:"pool_id"`
//		}
func GetRunnerSpecFromBootstrapParams(data params.BootstrapInstance) (runnerSpec, error) {
	tools, err := util.GetTools(data.OSType, data.OSArch, data.Tools)
	if err != nil {
		return runnerSpec{}, fmt.Errorf("failed to get tools: %s", err)
	}

	extraSpecs := newExtraSpecsFromBootstrapData(data)
	return runnerSpec{
		AllocatePublicIP:   extraSpecs.AllocatePublicIP,
		OpenInboundPorts:   extraSpecs.OpenInboundPorts,
		AdminUsername:      extraSpecs.AdminUsername,
		StorageAccountType: extraSpecs.StorageAccountType,
		DiskSizeGB:         extraSpecs.DiskSizeGB,
		UseCloudInit:       extraSpecs.UseCloudInit,
		BootstrapParams:    data,
		Tools:              tools,
	}, nil
}

type runnerSpec struct {
	VMSize             string
	AllocatePublicIP   bool
	AdminUsername      string
	OSPlatform         string
	StorageAccountType armcompute.StorageAccountTypes
	DiskSizeGB         int32
	OpenInboundPorts   map[armnetwork.SecurityRuleProtocol][]int
	BootstrapParams    params.BootstrapInstance
	Tools              github.RunnerApplicationDownload
	UseCloudInit       bool
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

func (r runnerSpec) composeCloudInitUserdata() (string, error) {
	udata, err := util.GetCloudConfig(r.BootstrapParams, r.Tools, r.BootstrapParams.Name)
	if err != nil {
		return "", fmt.Errorf("failed to generate userdata: %w", err)
	}
	return udata, nil
}

func (r runnerSpec) composeWindowsUserdata() (string, error) {
	return "", nil
}

func (r runnerSpec) composeLinuxUserdata() (string, error) {
	return "", nil
}

func (r runnerSpec) ComposeUserData() (string, error) {
	switch r.BootstrapParams.OSType {
	case params.Linux:
		if r.UseCloudInit {
			return r.composeCloudInitUserdata()
		}
		return r.composeLinuxUserdata()
	case params.Windows:
		return r.composeWindowsUserdata()
	}
	return "", fmt.Errorf("unsupported OS type for cloud config: %s", r.BootstrapParams.OSType)
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
