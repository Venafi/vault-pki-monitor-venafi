package pki

import (
	"context"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"log"
	"os"
	"strings"
	"testing"
)

const msg_denied_by_policy = "certificate issue should be denied by policy, %#v"
const wrong_csr = `-----BEGIN CERTIFICATE REQUEST-----
MIICYDCCAUgCAQAwGzEZMBcGA1UEAwwQdGVzdC53cm9uZy53cm9uZzCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBALjZph++4eMekq0gQyCHr9sU3vF7hu6C
9j+BpAGHIuaIcfTSPV6JeZVgmUy5aDb0vAx4s76oXsM9VWpdTz7oU70S4wZCrKl9
1gbZpGkt+BnqLjgUe6OXj8CAQi10oxDcj9o08Iln1l5CrsHc2HdrRIULcdc+R3L3
4wVJg8x1FbbnLn1WB1h3KVJk1f831H7I7tp1AxqYbtjsTb8VzX8ub1537bWzIwf0
8Taixa4Rrd8DjpttI3A4PzyprbfKfHXPCYpLg/KFRF7N1sVTPeByQ78qM93pXeeV
W5+mhFptKCY2nv723ZPD45GYutjWLUQq0VSXbpAOH/Ph/HXnliXHtMUCAwEAAaAA
MA0GCSqGSIb3DQEBCwUAA4IBAQCRgyRmDtrBoUXYF5y7vgyZyO79+1MzKlwS+5wt
IAgwIF2z+uyr7zo3bmNy9TaFDX8scdFcfdiHqeAEjvjD+qSD9I5PC71cTgoAKWUF
IVzizZVziVOTfNXllNwr/zfFzD7biKiTIG+81ZOOw+UtD7/aSeGMrj55S+RIXkPa
E4zs31QF9oVpfbi2BubneCU808ShsWIrSzjbiLZ/D/IHDFuoX7tbdZSmVU+mlx/r
9LEUz2Cmyq58JRJ78KtRUYDtCulYjhz0NWW8tcG+95K750rd02v1UkZSKulyWf8/
0OPEbiZxi54VpqfWOC5x0YwUCmvktKm4X0/JbX6ISxRvnx7z
-----END CERTIFICATE REQUEST-----
`
const allowed_csr = `-----BEGIN CERTIFICATE REQUEST-----
MIIEXzCCAkcCAQAwGjEYMBYGA1UEAwwPdGVzdC52ZmlkZXYuY29tMIICIjANBgkq
hkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAv0UEj15pL44I/ljSWdlPJpwMr2IAaxM3
tCzKHtISp18JyXSKvzbKSCusWhM3KZ9Z+d+qhXds+v8AWFvcf0O+DOA2ZOic1lK5
PwtXKFLOJjXzG22rzAYb/7QUGNlhFgZd6Ur3QLhEDijNfmcXGDzZYsGpF4LXyaKG
hvifMqe04U4TzRI9aErzXNWQLBGR+tN3f5FGB6gqS1xeZnoo4fd9KwCvksOBK8Jk
4pkAcRe990ktpN2F0ZgbAg++lBqzTm6WUlREQbByx2j0g8KIDme4KzPcclyhT7NF
ziVMRPstXkBJ5ep7FG3zr3bfaU0K6uw21aEWYyLPxhV//MMiiKbOUAEVFnrLV4I+
7mbbW0+jKM/4TU1sq+2YI5h99gQYCh1fSXHc0gFu8/egqWvW1hvEZTWU5E6hN0MQ
Qgrwl64flXyl1nUmrTtm7ru7O/88Qij/5gmyLkAhll/iMcaWfk/pw/kKYFJrGSc5
Qv3yaDDV+ckjzwM18H1PkcgHAaiK3qs2MI720QP+qa8DuHMebIE7Po5LneKtYwxc
B0QpuU4xyzxBwgT8ztPQvn9fKPbt/MLBQ+zqIzj1mdNni/ylqH8ssXi81pJp1+mX
zbDArq1LXE/t6vJeyyzVpXjmfLQ3KpJ2pSlAZI1Pfpy4YE63jFQFABcW4Pij6cP/
vBpXhcjT760CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4ICAQCiKRv41NybHGFPjYSi
vEmYa8RIIWkoM66O59s9aoKxvaXMCdjQmDYsfHn6Nlx7P1xz4U8XRWVYT7t13aGo
GFguvUS+HdthBXIUAMrnOB6ttrJfFasnA7/VqkPjd2nZYFJacoDaAOwuF4BEwfXn
rLQIaAZkZ/oHaMulgCuAj8SjxjR4sonFcC3D1WoT6rpY+74LDjNg+vl6COJ+37Sc
3xFjaoj+aJP5eegijQ0QEEPPKLSHo0dsnUPl2/YViZ2FGqfqi02HdFYj0BI4Eh3F
O/Or2E7/gtvwdLNITgG1hPv+VqBJkpFfNBVUk4loxgXR3Qd5qsBwMO8EIF3h1YK8
5rkXfokTTABEJNuGCv8rZi3MASLM1Z3kiexJrhQPeHV8xGpyhv9IPT6XUEZ7OaY2
h+Q2csT7GBiIAb0KygU8bbK7koOTH1cX+dv8kXWiJcTW0fzstZsR2fw/ra1S4oxJ
eB8YUXRem8xBJvBQfUM0sdJR9bao8xBiZ+jCejCkpg3MpMz/CthCijWcg9JFhabT
hAtoeB7AX9LqxyYikVrjxf45UfcAzeIZgf81XJqVW0FgZLNxMSM99ySeVco/nGsJ
JEwcoOowfcflK/mXRHsN65p1p/v9OWGFkwnFPeM56QpP68r8AluAN86sfb3JqpFn
jM0aRZ4bdyObnjtOEUFktgRNNA==
-----END CERTIFICATE REQUEST-----
`

var venafiCreateSimplePolicyStep = logicaltest.TestStep{
	Operation: logical.UpdateOperation,
	Path:      venafiPolicyPath + defaultVenafiPolicyName,
	Data: map[string]interface{}{
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPALLALLOWZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	},
}

func makeVenafiCloudConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	// Configure Venafi default policy
	policyData = map[string]interface{}{
		"cloud_url": os.Getenv("CLOUDURL"),
		"apikey":    os.Getenv("CLOUDAPIKEY"),
		"zone":      os.Getenv("CLOUDRESTRICTEDZONE"),
	}
	return
}

func makeVenafiTPPConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	// Configure Venafi default policy
	policyData = map[string]interface{}{
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPRESTRICTEDZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	}
	return
}

func TestVenafiPolicyCloud(t *testing.T) {
	domain, policyData := makeVenafiCloudConfig()
	venafiPolicyTests(t, policyData, domain)
}

func TestVenafiPolicyTPP(t *testing.T) {
	domain, policyData := makeVenafiTPPConfig()
	venafiPolicyTests(t, policyData, domain)
}

func TestVenafiPolicyCloudSignBeforeConfigure(t *testing.T) {
	domain, _ := makeVenafiCloudConfig()
	venafiPolicyTestSignBeforeConfigure(t, domain)
}

func TestVenafiPolicyTPPSignBeforeConfigure(t *testing.T) {
	domain, _ := makeVenafiCloudConfig()
	venafiPolicyTestSignBeforeConfigure(t, domain)
}

func venafiPolicyTestSignBeforeConfigure(t *testing.T, domain string) {
	b, storage := createBackendWithStorage(t)
	rootData := map[string]interface{}{
		"common_name": domain,
		"ttl":         "6h",
	}
	resp, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "root/generate/internal",
		Storage:   storage,
		Data:      rootData,
	})
	if resp == nil {
		t.Fatalf("Error should be generated in response")
	}
	if resp.Error() == nil {
		t.Fatalf("Should fail to generate root before configuring policy")
	}
}

func TestVenafiPolicyCloudWriteAndReadPolicy(t *testing.T) {
	_, policyData := makeVenafiCloudConfig()
	venafiPolicyWriteAndReadTest(t, policyData)
}

func TestVenafiPolicyTPPWriteAndReadPolicy(t *testing.T) {
	_, policyData := makeVenafiTPPConfig()
	venafiPolicyWriteAndReadTest(t, policyData)
}

func venafiPolicyWriteAndReadTest(t *testing.T, policyData map[string]interface{}) {
	// create the backend
	b, storage := createBackendWithStorage(t)

	resp := writePolicy(b, storage, policyData, t)

	log.Println("After write policy should be on output")
	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read saved policy configuration")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName,
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from "+venafiPolicyPath+defaultVenafiPolicyName+"/policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Check expected policy config properties")
	if resp.Data["zone"].(string) != policyData["zone"] {
		t.Fatalf("%s != %s", resp.Data["zone"].(string), policyData["zone"])
	}

	log.Println("Read saved Venafi policy content")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName + "/policy",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from "+venafiPolicyPath+defaultVenafiPolicyName+"policy, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read Venafi policy content from wrong path")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      venafiPolicyPath + "wrong-path/policy",
		Storage:   storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["error"] != "policy data is nil. Looks like it doesn't exists." {
		t.Fatalf("should faile to read venafi policy from "+venafiPolicyPath+"wrong-path/policy, %#v", resp)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

}

func writePolicy(b *backend, storage logical.Storage, policyData map[string]interface{}, t *testing.T) *logical.Response {
	log.Println("Writing Venafi policy configuration")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName,
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
		t.Fatalf("after write policy should be on output, but response is nil: %#v", resp)
	}
	return resp
}

func writePolicyToClient(mountPoint string, client *api.Client, t *testing.T) {
	_, err := client.Logical().Write(mountPoint+"/"+venafiPolicyPath+defaultVenafiPolicyName, venafiCreateSimplePolicyStep.Data)
	if err != nil {
		t.Fatal(err)
	}
}

func venafiPolicyTests(t *testing.T, policyData map[string]interface{}, domain string) {
	// create the backend
	rand := randSeq(9)
	b, storage := createBackendWithStorage(t)
	writePolicy(b, storage, policyData, t)

	log.Println("Setting up role")
	roleData := map[string]interface{}{
		"organization": "Venafi Inc.",
		"ou":           "Integration",
		"locality":     "Salt Lake",
		"province":     "Utah",
		"country":      "US",
		"allowed_domains":    domain,
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
		"common_name": "ca." + domain,
		"ttl":         "6h",
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

	log.Println("issue proper cert")
	singleCN := rand + "-policy." + domain
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

	log.Println("issue cert with wrong CN")
	singleCN = rand + "-import." + "wrong.wrong"
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err_msg, prsnt := resp.Data["error"]; prsnt {
		if !strings.Contains(err_msg.(string), "doesn't match regexps") {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	} else {
		t.Fatalf(msg_denied_by_policy, resp)
	}

	wrong_params := map[string]string{
		"organization": "Wrong Organization",
		"ou":           "Wrong Organization Unit",
		"locality":     "Wrong Locality",
		"province":     "Wrong State",
		"country":      "Wrong Country",
	}

	for key, value := range wrong_params {
		log.Println("Setting up role with wrong", key)
		wrongRoleData := map[string]interface{}{
			"allowed_domains":    domain,
			"allow_subdomains":   "true",
			"max_ttl":            "4h",
			"allow_bare_domains": true,
			"generate_lease":     true,
			key:                  value,
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/test-venafi-policy",
			Storage:   storage,
			Data:      wrongRoleData,
		})

		if resp != nil && resp.IsError() {
			t.Fatalf("failed to create a role, %#v", resp)
		}
		if err != nil {
			t.Fatal(err)
		}

		log.Println("issue cert with wrong", key)
		singleCN = rand + "-policy." + domain
		certData = map[string]interface{}{
			"common_name": singleCN,
		}

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "issue/test-venafi-policy",
			Storage:   storage,
			Data:      certData,
		})
		if err != nil {
			t.Fatal(err)
		}

		if err_msg, prsnt := resp.Data["error"]; prsnt {
			if !strings.Contains(err_msg.(string), "doesn't match regexps") {
				t.Fatalf(msg_denied_by_policy, resp)
			}
		} else {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	}

	log.Println("Write normal parameters back")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-policy",
		Storage:   storage,
		Data:      roleData,
	})

	//TODO: add tests for CSR
	log.Println("Testing wrong CSR signing")
	certData = map[string]interface{}{
		"csr": wrong_csr,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err_msg, prsnt := resp.Data["error"]; prsnt {
		if !strings.Contains(err_msg.(string), "doesn't match regexps") {
			t.Fatalf(msg_denied_by_policy, resp)
		}
	} else {
		t.Fatalf(msg_denied_by_policy, resp)
	}

	log.Println("Testing proper CSR signing")
	certData = map[string]interface{}{
		"csr": allowed_csr,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	if resp.Data["certificate"] == nil {
		t.Fatalf("certificate field shouldn't be nil, %#v", resp)
	}

	//TODO: add test with wrong key types

	log.Println("Writing second Venafi policy configuration")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiPolicyPath + "second",
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
		t.Fatalf("after write policy should be on output, but response is nil: %#v", resp)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys := resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)

	log.Println("Deleting Venafi policy default")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      venafiPolicyPath + defaultVenafiPolicyName,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete policy, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys = resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)
	//TODO: check that keys is list of [default second]

	log.Println("Creating PKI role for policy second")
	roleData["venafi_check_policy"] = "second"
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-venafi-second-policy",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	log.Println("Issuing certificate for policy second")
	singleCN = rand + "-import-second-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-second-policy",
		Storage:   storage,
		Data:      certData,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	log.Println("Deleting Venafi policy second")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      venafiPolicyPath + "second",
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to delete policy, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	log.Println("Listing Venafi policies")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      venafiPolicyPath,
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list policies, %#v", resp)
	}

	if err != nil {
		t.Fatal(err)
	}

	keys = resp.Data["keys"]
	log.Printf("Policy list is:\n %v", keys)
	//TODO: check that keys is list of [second]

	log.Println("Trying to sign certificate with deleted policy")
	singleCN = rand + "-import-deleted-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-venafi-policy",
		Storage:   storage,
		Data:      certData,
	})
	if resp == nil {
		t.Fatalf("Error should be generated in response")
	}
	if resp.Error() == nil {
		t.Fatalf("Should fail to generate certificate after deleting policy")
	}

}
