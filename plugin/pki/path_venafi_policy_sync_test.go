package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"testing"
)

var policyTPPData = map[string]interface{}{
	"tpp_url":           os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var policyCloudData =  map[string]interface{}{
	"apikey":                os.Getenv("CLOUD_APIKEY"),
	"cloud_url":             os.Getenv("CLOUD_URL"),
	"zone":                  os.Getenv("CLOUD_ZONE_RESTRICTED"),
}

var wantTPPRoleEntry = roleEntry{
	Organization:   []string{"Venafi Inc."},
	OU:             []string{"Integrations"},
	Locality:       []string{"Salt Lake"},
	Province:       []string{"Utah"},
	Country:        []string{"US"},
	AllowedDomains: []string{},
	KeyUsage: []string{"CertSign"},
}

var wantCloudRoleEntry = roleEntry{
	Organization:   []string{"Venafi Inc."},
	OU:             []string{"Integrations"},
	Locality:       []string{"Salt Lake"},
	Province:       []string{"Utah"},
	Country:        []string{"US"},
	AllowedDomains: []string{},
	KeyUsage: []string{"CertSign"},
}

var wantTPPRoleEntry2 = roleEntry{
	Organization:   []string{"Venafi2"},
	OU:             []string{"Integrations2"},
	Locality:       []string{"Salt2"},
	Province:       []string{"Utah2"},
	Country:        []string{"FR"},
	AllowedDomains: []string{},
	KeyUsage: []string{"CertSign"},
}

var roleData = map[string]interface{}{
	"organization":       "Default",
	"ou":                 "Default",
	"locality":           "Default",
	"province":           "Default",
	"country":            "Default",
	"allowed_domains":    "example.com",
	"allow_subdomains":   "true",
	"max_ttl":            "4h",
	"key_usage": "CertSign",
	"allow_bare_domains": true,
	"generate_lease":     true,
	"venafi_sync":        true,
}

func TestSyncRoleWithTPPPolicy(t *testing.T) {
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
	writePolicy(b, storage, policyTPPData, t)
	roleData["venafi_sync_zone"] = os.Getenv("TPP_ZONE")
	roleData["venafi_sync_policy"] = defaultVenafiPolicyName

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

	ctx := context.Background()
	err = b.syncWithVenafiPolicy(storage)
	if err != nil {
		t.Fatal(err)
	}

	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	t.Log("Checking modified role entry")
	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)
}

func TestSyncRoleWithCloudPolicy(t *testing.T) {
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
	writePolicy(b, storage, policyCloudData, t)
	roleData["venafi_sync_zone"] = os.Getenv("CLOUD_ZONE_RESTRICTED")
	roleData["venafi_sync_policy"] = defaultVenafiPolicyName

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

	ctx := context.Background()
	err = b.syncWithVenafiPolicy(storage)
	if err != nil {
		t.Fatal(err)
	}

	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	t.Log("Checking modified role entry")
	checkRoleEntry(t, *roleEntryData, wantCloudRoleEntry)
}

func TestSyncMultipleRolesWithTPPPolicy(t *testing.T) {
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

	writePolicy(b, storage, policyTPPData, t)
	t.Log("Setting up first role")

	roleData["venafi_sync_zone"] = os.Getenv("TPP_ZONE")
	roleData["venafi_sync_policy"] = defaultVenafiPolicyName

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
	err = b.syncWithVenafiPolicy(storage)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Checking data for the first role")
	roleEntryData, err := b.getPKIRoleEntry(ctx, storage, testRoleName)

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry)

	t.Log("Checking data for the second role")
	roleEntryData, err = b.getPKIRoleEntry(ctx, storage, testRoleName+"-second")

	if err != nil {
		t.Fatal(err)
	}

	if roleEntryData == nil {
		t.Fatal("role entry should not be nil")
	}

	checkRoleEntry(t, *roleEntryData, wantTPPRoleEntry2)
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

	ctx := context.Background()
	entry, err := b.getPKIRoleEntry(ctx, storage, "test-venafi-role")
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
	ctx := context.Background()

	writePolicy(b, storage, policyTPPData, t)
	venafiPolicyEntry, err := b.getVenafiPolicyParams(ctx, storage, defaultVenafiPolicyName, policyTPPData["zone"].(string))
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
