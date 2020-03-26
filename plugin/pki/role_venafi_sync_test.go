package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"os"
	"testing"
)

func TestSyncRoleWithPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	//write TPP policy
	policyData := map[string]interface{}{
		"tpp_url":           os.Getenv("TPP_URL"),
		"tpp_user":          os.Getenv("TPP_USER"),
		"tpp_password":      os.Getenv("TPP_PASSWORD"),
		"zone":              os.Getenv("TPP_ZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	}

	writePolicy(b, storage, policyData, t)
	log.Println("Setting up role")
	roleData := map[string]interface{}{
		"organization":       "Venafi Inc.",
		"ou":                 "Integration",
		"locality":           "Salt Lake",
		"province":           "Utah",
		"country":            "US",
		"allowed_domains":    "example.com",
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-policy",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	rootData := map[string]interface{}{
		"common_name":  "ca.some.domain",
		"organization": "Venafi Inc.",
		"ou":           "Integration",
		"locality":     "Salt Lake",
		"province":     "Utah",
		"country":      "US",
		"ttl":          "6h",
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to generate internal root CA, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	// config urls
	urlsData := map[string]interface{}{
		"issuing_certificates":    "http://127.0.0.1:8200/v1/pki/ca",
		"crl_distribution_points": "http://127.0.0.1:8200/v1/pki/crl",
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/urls",
		Storage:   storage,
		Data:      urlsData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to config urls, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := &logical.Request{
		Storage:   storage,
	}
    err = b.roleVenafiSync(ctx,req)
	if err != nil {
		t.Fatal(err)
	}
}
