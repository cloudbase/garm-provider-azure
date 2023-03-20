package config

import (
	"fmt"
	"os"

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
}

func (c *Config) GetCredentials() (azcore.TokenCredential, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("error validating config: %w", err)
	}

	creds, err := c.Credentials.Auth()
	if err != nil {
		return nil, fmt.Errorf("failed to get authentication token: %w", err)
	}

	return creds, nil
}

func (c *Config) Validate() error {
	if _, err := c.Credentials.Auth(); err != nil {
		return fmt.Errorf("failed to validate credentials: %w", err)
	}

	return nil
}

type Credentials struct {
	Name        string `toml:"name"`
	Description string `toml:"description"`

	TenantID       string            `toml:"tenant_id"`
	ClientID       string            `toml:"client_id"`
	SubscriptionID string            `toml:"subscription_id"`
	UserPassword   UserPassword      `toml:"password_auth"`
	CertAuth       ClientCertificate `toml:"cert_auth"`
	SecretAuth     ClientSecret      `toml:"secret_auth"`
	// ClientOptions is the azure identity client options that will be used to authenticate
	// againsts an azure cloud. This is a heavy handed approach for now, defining the entire
	// ClientOptions here, but should allow users to use this provider with AzureStack or any
	// other azure cloud besides Azure proper (like Azure China, Germany, etc).
	ClientOptions azcore.ClientOptions `toml:"client_options"`
}

func (c Credentials) Validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("missing tenant_id")
	}

	if c.ClientID == "" {
		return fmt.Errorf("missing client_id")
	}

	if c.SubscriptionID == "" {
		return fmt.Errorf("missing subscription_id")
	}

	if c.UserPassword.HasCredentials() {
		return nil
	}

	if c.CertAuth.HasCredentials() {
		return nil
	}

	if c.SecretAuth.HasCredentials() {
		return nil
	}

	return fmt.Errorf("no valid credentials were specified")
}

func (c Credentials) Auth() (azcore.TokenCredential, error) {
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("validating credentials: %w", err)
	}

	if c.UserPassword.HasCredentials() {
		o := &azidentity.UsernamePasswordCredentialOptions{ClientOptions: c.ClientOptions}
		cred, err := azidentity.NewUsernamePasswordCredential(c.TenantID, c.ClientID, c.UserPassword.Username, c.UserPassword.Password, o)
		if err != nil {
			return nil, err
		}
		return cred, nil
	}

	if c.SecretAuth.HasCredentials() {
		o := &azidentity.ClientSecretCredentialOptions{ClientOptions: c.ClientOptions}
		cred, err := azidentity.NewClientSecretCredential(c.TenantID, c.ClientID, c.SecretAuth.ClientSecret, o)
		if err != nil {
			return nil, err
		}
		return cred, nil
	}

	if c.CertAuth.HasCredentials() {
		certData, err := os.ReadFile(c.CertAuth.CertificatePath)
		if err != nil {
			return nil, fmt.Errorf(`failed to read certificate file "%s": %v`, c.CertAuth.CertificatePath, err)
		}
		var password []byte
		if v := os.Getenv(c.CertAuth.CertificatePassword); v != "" {
			password = []byte(v)
		}
		certs, key, err := azidentity.ParseCertificates(certData, password)
		if err != nil {
			return nil, fmt.Errorf(`failed to load certificate from "%s": %v`, c.CertAuth.CertificatePath, err)
		}
		o := &azidentity.ClientCertificateCredentialOptions{ClientOptions: c.ClientOptions, SendCertificateChain: c.CertAuth.SendCertificateChain}
		cred, err := azidentity.NewClientCertificateCredential(c.TenantID, c.ClientID, certs, key, o)
		if err != nil {
			return nil, err
		}
		return cred, nil
	}

	return nil, fmt.Errorf("failed to get credentials")
}

type UserPassword struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

func (u UserPassword) HasCredentials() bool {
	if u.Username != "" && u.Password != "" {
		return true
	}
	return false
}

type ClientCertificate struct {
	CertificatePath      string `toml:"certificate_path"`
	CertificatePassword  string `toml:"certificate_password"`
	SendCertificateChain bool   `toml:"send_certificate_chain"`
}

func (c ClientCertificate) HasCredentials() bool {
	if c.CertificatePath != "" {
		if _, err := os.Stat(c.CertificatePath); err == nil {
			return true
		}
	}
	return false
}

type ClientSecret struct {
	ClientSecret string `toml:"client_secret"`
}

func (c ClientSecret) HasCredentials() bool {
	return c.ClientSecret != ""
}
