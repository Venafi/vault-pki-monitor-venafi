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
)

func (b *backend) ClientVenafi(ctx context.Context, s logical.Storage, req *logical.Request, roleName string) (
	endpoint.Connector, error) {
	if roleName == "" {
		return nil, fmt.Errorf("Missing role name")
	}
	log.Printf("Using role: %s", roleName)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("Unknown role %v", role)
	}

	log.Printf("Using Venafi Platform with url %s\n", role.TPPURL)
	cfg := &vcert.Config{
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
