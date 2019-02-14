package pki

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"io/ioutil"
	"log"
	"math/rand"
	"time"
)

//Set it false to disable Venafi policy check. It can be done only on the code level of the plugin.
const VenafiPolciyCheck = true

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, req *logical.Request, configName string, configType string) (
	endpoint.Connector, error) {

	var cfg *vcert.Config

	if configType == "role" {
		if configName == "" {
			return nil, fmt.Errorf("missing role name")
		}
		log.Printf("Using role: %s", configName)

		role, err := b.getRole(ctx, req.Storage, configName)
		if err != nil {
			return nil, err
		}
		if role == nil {
			return nil, fmt.Errorf("unknown role %v", role)
		}

		log.Printf("Using Venafi Platform with url %s\n", role.TPPURL)
		cfg = &vcert.Config{
			ConnectorType: endpoint.ConnectorTypeTPP,
			BaseUrl:       role.TPPURL,
			Credentials: &endpoint.Authentication{
				User:     role.TPPUser,
				Password: role.TPPPassword,
			},
			Zone:       role.Zone,
			LogVerbose: true,
		}
		if role.TrustBundleFile != "" {
			trustBundle, err := ioutil.ReadFile(role.TrustBundleFile)
			if err != nil {
				log.Printf("Can`t read trust bundle from file %s: %v\n", role.TrustBundleFile, err)
				return nil, err
			}
			cfg.ConnectionTrust = string(trustBundle)
		}

	} else if configType == "policy" {
		if configName == "" {
			return nil, fmt.Errorf("missing policy name")
		}

		policy, err := b.getPolicyConfig(ctx, req.Storage, configName)
		if err != nil {
			return nil, err
		}
		if policy == nil {
			return nil, fmt.Errorf("unknown policy %v", policy)
		}

		log.Printf("Using policy: %s", configName)
		if policy.TPPURL != "" && policy.TPPUser != "" && policy.TPPPassword != "" {
			log.Printf("Using Platform with url %s to issue certificate\n", policy.TPPURL)
			if policy.TrustBundleFile != "" {
				log.Printf("Trying to read trust bundle from file %s\n", policy.TrustBundleFile)
				trustBundle, err := ioutil.ReadFile(policy.TrustBundleFile)
				if err != nil {
					return nil, err
				}
				trustBundlePEM := string(trustBundle)
				cfg = &vcert.Config{
					ConnectorType:   endpoint.ConnectorTypeTPP,
					BaseUrl:         policy.TPPURL,
					ConnectionTrust: trustBundlePEM,
					Credentials: &endpoint.Authentication{
						User:     policy.TPPUser,
						Password: policy.TPPPassword,
					},
					Zone:       policy.Zone,
					LogVerbose: true,
				}
			} else {
				cfg = &vcert.Config{
					ConnectorType: endpoint.ConnectorTypeTPP,
					BaseUrl:       policy.TPPURL,
					Credentials: &endpoint.Authentication{
						User:     policy.TPPUser,
						Password: policy.TPPPassword,
					},
					Zone:       policy.Zone,
					LogVerbose: true,
				}
			}
		} else if policy.Apikey != "" {
			log.Println("Using Cloud to issue certificate")
			cfg = &vcert.Config{
				ConnectorType: endpoint.ConnectorTypeCloud,
				BaseUrl:       policy.CloudURL,
				Credentials: &endpoint.Authentication{
					APIKey: policy.Apikey,
				},
				Zone:       policy.Zone,
				LogVerbose: true,
			}
		} else {
			return nil, fmt.Errorf("failed to build config for Venafi issuer")
		}
	} else {
		return nil, fmt.Errorf("couldn't determine config type")
	}

	client, err := vcert.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to get Venafi issuer client: %s", err)
	}

	return client, nil
}

func pp(a interface{}) string {
	b, err := json.MarshalIndent(a, "", "    ")
	if err != nil {
		fmt.Println("error:", err)
	}
	return fmt.Sprintf(string(b))
}

func randSeq(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
