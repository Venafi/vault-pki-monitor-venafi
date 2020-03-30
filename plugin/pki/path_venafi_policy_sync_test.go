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
	testRoleName := "test-venafi-role"
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
		"organization":       "Default",
		"ou":                 "Default",
		"locality":           "Default",
		"province":           "Default",
		"country":            "Default",
		"allowed_domains":    "example.com",
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
		"venafi_sync":        true,
		"venafi_sync_zone":   os.Getenv("TPP_ZONE"),
		"venafi_sync_policy": defaultVenafiPolicyName,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
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
		Storage: storage,
	}
	err = b.roleVenafiSync(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	roleEntryData, err := b.getPKIRoleEntry(ctx, req, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)
}

func TestSyncMultipleRolesWithPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	testRoleName := "test-venafi-role"
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
	t.Log("Setting up first role")
	roleData := map[string]interface{}{
		"organization":       "Default",
		"ou":                 "Default",
		"locality":           "Default",
		"province":           "Default",
		"country":            "Default",
		"allowed_domains":    "example.com",
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
		"venafi_sync":        true,
		"venafi_sync_zone":   os.Getenv("TPP_ZONE"),
		"venafi_sync_policy": defaultVenafiPolicyName,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName,
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Setting up second role")
	roleData["venafi_sync_zone"] = os.Getenv("TPP_ZONE2")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + testRoleName + "-second",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	req := &logical.Request{
		Storage: storage,
	}
	err = b.roleVenafiSync(ctx, req)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Checking data for the first role")
	roleEntryData, err := b.getPKIRoleEntry(ctx, req, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)

	t.Log("Checking data for the second role")
	roleEntryData, err = b.getPKIRoleEntry(ctx, req, testRoleName+"-second")

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry2)
}

var wantTPPRoleEntry = roleEntry{
	Organization:   []string{"Venafi Inc."},
	OU:             []string{"Integrations"},
	Locality:       []string{"Salt Lake"},
	Province:       []string{"Utah"},
	Country:        []string{"US"},
	AllowedDomains: []string{"example.com"},
}

var wantTPPRoleEntry2 = roleEntry{
	Organization:   []string{"Venafi2"},
	OU:             []string{"Integrations2"},
	Locality:       []string{"Salt2"},
	Province:       []string{"Utah2"},
	Country:        []string{"FR"},
	AllowedDomains: []string{"example.com"},
}

func Test_backend_getPKIRoleEntry(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

	roleData := map[string]interface{}{
		"organization":       "Default",
		"ou":                 "Default",
		"locality":           "Default",
		"province":           "Default",
		"country":            "Default",
		"allowed_domains":    "example.com",
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-role",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	req := &logical.Request{
		Storage: storage,
	}
	ctx := context.Background()
	entry, err := b.getPKIRoleEntry(ctx, req, "test-venafi-role")
	if entry == nil {
		t.Fatal("role entry should not be nil")
	}
	var want string
	var have string

	want = roleData["organization"].(string)
	have = entry.Organization[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = roleData["ou"].(string)
	have = entry.OU[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = roleData["locality"].(string)
	have = entry.Locality[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = roleData["province"].(string)
	have = entry.Province[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}
}

func Test_backend_getVenafiPolicyParams(t *testing.T) {
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

	req := &logical.Request{
		Storage: storage,
	}
	ctx := context.Background()

	writePolicy(b, storage, policyData, t)
	venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, req, defaultVenafiPolicyName, policyData["zone"].(string))
	if err != nil {
		t.Fatal(err)
	}

	var want string
	var have string

	want = wantTPPRoleEntry.Organization[0]
	have = venafiPolicyEntry.Organization[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = wantTPPRoleEntry.OU[0]
	have = venafiPolicyEntry.OU[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}
}