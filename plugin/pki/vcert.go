package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
	"io/ioutil"
	"log"
)

//Set it false to disable Venafi policy check. It can be done only on the code level of the plugin.
const venafiPolciyCheck = true
const venafiPolicyDenyAll = true

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, policyName string) (
	endpoint.Connector, error) {

	if policyName == "" {
		return nil, fmt.Errorf("empty policy name")
	}

	policy, err := b.getVenafiPolicyConfig(ctx, s, policyName)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("expected policy but got nil from Vault storage %v", policy)
	}

	return policy.venafiConnectionConfig.getConnection()
}

func (b *backend) getConfing(ctx context.Context, s logical.Storage, policyName string) (
	*vcert.Config, error) {

	if policyName == "" {
		return nil, fmt.Errorf("empty policy name")
	}

	policy, err := b.getVenafiPolicyConfig(ctx, s, policyName)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		return nil, fmt.Errorf("expected policy but got nil from Vault storage %v", policy)
	}

	return policy.venafiConnectionConfig.getConfig(true)
}

func pp(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return fmt.Sprint(string(b))
}

type venafiConnectionConfig struct {
	TPPURL          string `json:"tpp_url"`
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

func (c venafiConnectionConfig) getConnection() (endpoint.Connector, error) {

	cfg, err := c.getConfig(false)
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

func (c venafiConnectionConfig) getConfig(includeRefToken bool) (*vcert.Config, error) {
	var cfg = &vcert.Config{
		Zone:       c.Zone,
		LogVerbose: true,
	}

	if c.URL != "" && c.AccessToken != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.BaseUrl = c.URL
		cfg.Credentials = &endpoint.Authentication{
			AccessToken: c.AccessToken,
		}

		if c.TrustBundleFile != "" {
			trustBundle, err := ioutil.ReadFile(c.TrustBundleFile)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", c.TrustBundleFile, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}

		if includeRefToken {
			cfg.Credentials.RefreshToken = c.RefreshToken
		}

	} else if c.URL != "" && c.TPPUser != "" && c.TPPPassword != "" && c.AccessToken == "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.BaseUrl = c.URL
		cfg.Credentials = &endpoint.Authentication{
			User:     c.TPPUser,
			Password: c.TPPPassword,
		}

		if c.TrustBundleFile != "" {
			trustBundle, err := ioutil.ReadFile(c.TrustBundleFile)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", c.TrustBundleFile, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}

	} else if c.Apikey != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeCloud
		cfg.BaseUrl = c.URL
		cfg.Credentials = &endpoint.Authentication{
			APIKey: c.Apikey,
		}
	} else {
		return nil, fmt.Errorf("failed to build config for Venafi conection")
	}
	return cfg, nil
}
