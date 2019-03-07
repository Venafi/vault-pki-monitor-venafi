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
MIIFTDCCAzQCAQAwgaQxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRIwEAYD
VQQHDAlTYWx0IExha2UxFDASBgNVBAoMC1ZlbmFmaSBJbmMuMRQwEgYDVQQLDAtJ
bnRlZ3JhdGlvbjEfMB0GCSqGSIb3DQEJARYQZW1haWxAdmZpZGV2LmNvbTElMCMG
A1UEAwwcdGVzdC1jc3ItMzIzMTMxMzEudmZpZGV2LmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBALGdS+40Lj1qWDMl9+hKiUtn2/PJzRA0yGSf8xAp
3HAxm6iXWTMkHBmWdm22FhatXt+6qSb+k2el7jfHEyVesMaKqw91C3Ht9LVuXLK4
xdb2QlKz/AaBMbh9kVUD//NrJM0VbNxflDMG8EWEpZeE9qUDMQQ8eB1fwBf824TP
XskiIqzo5HkRWBHmxvvKL0NWCPG4gy33yTyNwH2MBA5xMb+584/TEQkEPQDl14gj
1uR2B1Ndd8V0Yv/UCu1PjM3Nn2CrcN2/dQLTSNoMhLt/woxdxDiUOzumUPJ1vBVg
fEjGA+EIq/IkDgSNz4h5dUhdnEiMxe2yIHNhrOeomIaTbiRPGaMV/0JLhNQin6ug
y0ws3Tk8MwM0s+FLka62LFea7WbT5qTlkhvnJZdlbPD8j5h0+OamLmhB5jvTlJUW
IPpC8fQx4wjYq0xX0R9FMd1YQInoEVwH6Hd57iv+aqGD90UkcfXKj8BvDD8WdRAI
l4IAKHxLUtNRFAU+hv99kwX8KRIkHLiVJg6AhRhvSm84ClYi4OPEEvaw70gNwOAO
JkpbOttmSALLVoVn30bdayW0m7UAfiWtI3Ax+okthdELfdHrPPZK7d0SCB3VCeGp
ydQEjHwwttqEFFnkcpPMMZez7XW6MwJi1mneXvWoRzhX+4gt7OkahHEL6Lhj14nY
d1rjAgMBAAGgYjBgBgkqhkiG9w0BCQ4xUzBRME8GA1UdEQRIMEaCIWFsdDEtdGVz
dC1jc3ItMzIzMTMxMzEudmZpZGV2LmNvbYIhYWx0Mi10ZXN0LWNzci0zMjMxMzEz
MS52ZmlkZXYuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQAwt3Jc78Z1j7fjxQrsBl8m
ofuqwjqbbtLPu9uYbW9ZHdKwq7zpKShT942UZckzPiQKxy8bXVQ1MDrEzpfJKOpp
1tAqvn9pN3B3qxYKZOjzEmZgdAT57NiZSziN2vSY89aF28Ppz8ZUOFsiOvwuFBvQ
LLQopJ6mJEvMlv8+7CCQzumeIVRnxBjqqXnfJCBW9Dwcf1pAnsQv7RFf4XwU86dY
8GyLtpsq4wOJqzjbReCSjIJydqE/12QLOgzpT8a4Z1Srh6ZHfxWzIiAUQvrE4hHM
Exs0kkcJkUutlwMeaPACZkg3Tigqc72Y6YUeruBhEST5ypRrZGJJGHJLqpEHSPBb
w9B20cUctGxUQ4h1ogNCrz5XWjM+Khv+k5rkPhTQo0OnVglTkSzWV9FLufgUyu3E
O/KCByFbOckP56UxGFvVReJREPqa3Ib3QvTgIi810fe5SSmunpRCYBnKeqq4IVi5
4kXQNuHvV2wntJyIfEWZub7eXnHqP6OBndbo/0y26wYwKFRAgZDshIyPQUe01YIF
Gr6H0CHR3dU7Py0S49pAA+Jc93up5w056w5zhmjiv5c2N7m44VYJuxpwqfwtFxFF
WNHMdQt0cab08o2FGdJ3gtN4Fp1Fq+BRkgnST3ZISozd6nZXLuejXWjC+jNDvU/e
H2IE+vUez839sw9RlLcjgw==
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
