package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
	"io/ioutil"
	"log"
)

//Set it false to disable Venafi policy check. It can be done only on the code level of the plugin.
const venafiPolicyCheck = true
var venafiPolicyDenyAll = true

func (b *backend) ClientVenafi(ctx context.Context, s *logical.Storage, policyName string) (
	endpoint.Connector, error) {

	if policyName == "" {
		return nil, fmt.Errorf("empty policy name")
	}

	config, err := b.getVenafiPolicyConfig(ctx, s, policyName)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("expected policy but got nil from Vault storage %v", config)
	}
	if config.VenafiSecret == "" {
		return nil, fmt.Errorf("empty Venafi secret name")
	}

	secret, err := b.getVenafiSecret(ctx, s, config.VenafiSecret)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("expected Venafi secret but got nil from Vault storage %v", secret)
	}

	if config.Zone != "" {
		b.Logger().Debug("Using zone from Venafi Policy.", "zone", config.Zone)
	} else {
		b.Logger().Debug("Using zone from Venafi secret since Policy zone not found.", "zone", secret.Zone)
	}

	return secret.getConnection(config.Zone)
}

func (b *backend) getConfig(ctx context.Context, s *logical.Storage, policyName string) (
	*vcert.Config, error) {

	if policyName == "" {
		return nil, fmt.Errorf("empty policy name")
	}

	config, err := b.getVenafiPolicyConfig(ctx, s, policyName)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("expected Policy config but got nil from Vault storage %v", config)
	}
	if config.VenafiSecret == "" {
		return nil, fmt.Errorf("empty Venafi secret name")
	}

	secret, err := b.getVenafiSecret(ctx, s, config.VenafiSecret)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("expected Venafi secret but got nil from Vault storage %v", secret)
	}

	if config.Zone != "" {
		b.Logger().Debug("Using zone [%s] from Policy.", config.Zone)
	} else {
		b.Logger().Debug("Using zone [%s] from venafi secret. Policy zone not found.", secret.Zone)
	}

	return secret.getConfig(config.Zone, true)
}

func pp(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return fmt.Sprint(string(b))
}

type venafiSecretEntry struct {
	TPPUrl          string `json:"tpp_url"`
	URL             string `json:"url"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	Zone            string `json:"zone"`
	TPPPassword     string `json:"tpp_password"`
	TPPUser         string `json:"tpp_user"`
	TrustBundleFile string `json:"trust_bundle_file"`
	Apikey          string `json:"apikey"`
	CloudURL        string `json:"cloud_url"`
}

func (c venafiSecretEntry) getConnection(zone string) (endpoint.Connector, error) {
	cfg, err := c.getConfig(zone, false)
	if err == nil {
		client, err := vcert.NewClient(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
		} else {
			return client, nil
		}

	} else {
		return nil, err
	}

}

func (c venafiSecretEntry) getConfig(zone string, includeRefreshToken bool) (*vcert.Config, error) {
	if zone == "" {
		zone = c.Zone
	}

	var cfg = &vcert.Config{
		BaseUrl:     c.URL,
		Zone:        zone,
		LogVerbose:  true,
		Credentials: &endpoint.Authentication{},
	}

	if c.URL != "" && c.AccessToken != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.AccessToken = c.AccessToken
		if includeRefreshToken {
			cfg.Credentials.RefreshToken = c.RefreshToken
		}

	} else if c.URL != "" && c.TPPUser != "" && c.TPPPassword != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.Credentials.User = c.TPPUser
		cfg.Credentials.Password = c.TPPPassword

	} else if c.Apikey != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.Credentials.APIKey = c.Apikey

	} else {
		return nil, fmt.Errorf("failed to build config for Venafi conection")
	}

	if cfg.ConnectorType == endpoint.ConnectorTypeTPP {
		if c.TrustBundleFile != "" {
			trustBundle, err := ioutil.ReadFile(c.TrustBundleFile)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", c.TrustBundleFile, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}
	}
	return cfg, nil
}

func (c venafiSecretEntry) getMaskString() string {
	return "********"
}
