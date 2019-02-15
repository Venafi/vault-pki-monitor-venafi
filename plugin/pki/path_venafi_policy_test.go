package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"log"
	"os"
	"testing"
)

func TestBackend_VenafiPolicyTPP(t *testing.T) {
	rand := randSeq(9)
	domain := "example.com"
	// Configure Venafi default policy
	policyData := map[string]interface{}{
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	}

	// create a role entry with default policy
	roleData := map[string]interface{}{
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
	}

	VenafiPolicyTests(t, policyData, roleData, rand, domain)
}

func TestBackend_VenafiPolicyCloud(t *testing.T) {
	rand := randSeq(9)
	domain := "example.com"
	// Configure Venafi default policy
	policyData := map[string]interface{}{
		"cloud_url": os.Getenv("CLOUDURL"),
		"apikey":    os.Getenv("CLOUDAPIKEY"),
		"zone":      os.Getenv("CLOUDZONE"),
	}

	// create a role entry with default policy
	roleData := map[string]interface{}{
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
	}

	VenafiPolicyTests(t, policyData, roleData, rand, domain)
}

func VenafiPolicyTests(t *testing.T, policyData map[string]interface{}, roleData map[string]interface{}, rand string, domain string) {

	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	// generate root
	rootData := map[string]interface{}{
		"common_name": domain,
		"ttl":         "6h",
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to generate root, %#v", resp)
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

	//Write Venafi policy configuration
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi-policy/default",
		Storage:   storage,
		Data:      policyData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure venafi policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {

	}

	log.Println("After write policy should be on output")
	if resp.Data["subject_cn_regexes"].([]string)[0] != ".*" {
		t.Fatalf("subject_cn_regexes is unexpected value")
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read saved Venafi policy")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "venafi-policy/default/policy",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from venafi-policy/default/policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//Check expected policy properties
	if resp.Data["subject_cn_regexes"].([]string)[0] != ".*" {
		t.Fatalf("subject_cn_regexes is unexpected value")
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
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

	// issue particular cert
	singleCN := rand + "-import." + domain
	certData := map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	//TODO: issuer certificate which won't match policy

}
