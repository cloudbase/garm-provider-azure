package provider

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

	"github.com/cloudbase/garm/params"
)

/*
	type BootstrapInstance struct {
		Name  string                              `json:"name"`
		Tools []*github.RunnerApplicationDownload `json:"tools"`
		// RepoURL is the URL the github runner agent needs to configure itself.
		RepoURL string `json:"repo_url"`
		// CallbackUrl is the URL where the instance can send a post, signaling
		// progress or status.
		CallbackURL string `json:"callback-url"`
		// MetadataURL is the URL where instances can fetch information needed to set themselves up.
		MetadataURL string `json:"metadata-url"`
		// InstanceToken is the token that needs to be set by the instance in the headers
		// in order to send updated back to the garm via CallbackURL.
		InstanceToken string `json:"instance-token"`
		// SSHKeys are the ssh public keys we may want to inject inside the runners, if the
		// provider supports it.
		SSHKeys []string `json:"ssh-keys"`
		// ExtraSpecs is an opaque raw json that gets sent to the provider
		// as part of the bootstrap params for instances. It can contain
		// any kind of data needed by providers. The contents of this field means
		// nothing to garm itself. We don't act on the information in this field at
		// all. We only validate that it's a proper json.
		ExtraSpecs json.RawMessage `json:"extra_specs,omitempty"`

		CACertBundle []byte `json:"ca-cert-bundle"`

		OSArch OSArch   `json:"arch"`
		Flavor string   `json:"flavor"`
		Image  string   `json:"image"`
		Labels []string `json:"labels"`
		PoolID string   `json:"pool_id"`
	}
*/
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
