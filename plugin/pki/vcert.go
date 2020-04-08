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

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, configName string, configType string) (
	endpoint.Connector, error) {

	if configName == "" {
		return nil, fmt.Errorf("missing %s name", configType)
	}

	log.Printf("Using %s: %s", configType, configName)
	if configType == "role" {
		role, err := b.getRole(ctx, s, configName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, fmt.Errorf("unknown role %v", role)
		}
		return role.venafiConnectionConfig.getConnection()

	} else if configType == "policy" {
		policy, err := b.getVenafiPolicyConfig(ctx, s, configName)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, fmt.Errorf("expected policy but got nil from Vault storage %v", policy)
		}

		return policy.venafiConnectionConfig.getConnection()
	} else {
		return nil, fmt.Errorf("couldn't determine config type")
	}
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
	Zone            string `json:"zone"`
	TPPPassword     string `json:"tpp_password"`
	TPPUser         string `json:"tpp_user"`
	TrustBundleFile string `json:"trust_bundle_file"`
	Apikey          string `json:"apikey"`
	CloudURL        string `json:"cloud_url"`
}

func (c venafiConnectionConfig) getConnection() (endpoint.Connector, error) {
	cfg := vcert.Config{
		Zone:       c.Zone,
		LogVerbose: true,
	}
	if c.TPPURL != "" && c.TPPUser != "" && c.TPPPassword != "" {
		cfg.ConnectorType = endpoint.ConnectorTypeTPP
		cfg.BaseUrl = c.TPPURL
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
		cfg.BaseUrl = c.CloudURL
		cfg.Credentials = &endpoint.Authentication{
			APIKey: c.Apikey,
		}
	} else {
		return nil, fmt.Errorf("failed to build config for Venafi conection")
	}
	client, err := vcert.NewClient(&cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}
	return client, nil
}
