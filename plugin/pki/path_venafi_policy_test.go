package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"log"
	"os"
	"strings"
	"testing"
)

const msg_denied_by_policy  = "certificate issue should be denied by policy, %#v"

func TestBackend_VenafiPolicyTPP(t *testing.T) {
	rand := randSeq(9)
	domain := "vfidev.com"
	// Configure Venafi default policy
	policyData := map[string]interface{}{
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	}

	VenafiPolicyTests(t, policyData, rand, domain, "tpp")
}

func TestBackend_VenafiPolicyCloud(t *testing.T) {
	rand := randSeq(9)
	domain := "vfidev.com"
	// Configure Venafi default policy
	policyData := map[string]interface{}{
		"cloud_url": os.Getenv("CLOUDURL"),
		"apikey":    os.Getenv("CLOUDAPIKEY"),
		"zone":      os.Getenv("CLOUDZONE"),
	}
	domain = "vfidev.com"
	// create a role entry with default policy

	VenafiPolicyTests(t, policyData,rand, domain, "cloud")
}

func VenafiPolicyTests(t *testing.T, policyData map[string]interface{}, rand string, domain string, endpoint string) {

	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}

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
	if resp == nil {
		t.Fatalf("Error should be generated in response")
	}
	if resp.Error() == nil {
		t.Fatalf("Should fail to generate root before configuring policy")
	}

	log.Println("Writing Venafi policy configuration")
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
		t.Fatalf("after write policy should be on output, but response is nil: %#v", resp)
	}

	log.Println("After write policy should be on output")
	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Read saved policy configuration")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "venafi-policy/default",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from venafi-policy/default/policy, %#v", resp)
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
		Path:      "venafi-policy/default/policy",
		Storage:   storage,
	})

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read venafi policy from venafi-policy/default/policy, %#v", resp)
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
		Path:      "venafi-policy/wrong-path/policy",
		Storage:   storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["error"] != "policy data is nil. Looks like it doesn't exists." {
		t.Fatalf("should faile to read venafi policy from venafi-policy/wrong-path/policy, %#v", resp)
	}

	for key, value := range resp.Data {
		log.Println(key, ":", value)
	}

	log.Println("Setting up role")
	roleData := map[string]interface{}{
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
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

	rootData = map[string]interface{}{
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
		"ou": "Wrong Organization Unit",
		"locality": "Wrong Locality",
		"province": "Wrong State",
		"country": "Wrong Country",
	}

	for key, value := range wrong_params {
		log.Println("Setting up role with wrong", key)
		wrongRoleData := map[string]interface{}{
			"allowed_domains":    domain,
			"allow_subdomains":   "true",
			"max_ttl":            "4h",
			"allow_bare_domains": true,
			"generate_lease":     true,
			key: value,
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


	//TODO: add test with wrong key types

	log.Println("Writing second Venafi policy configuration")
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi-policy/second",
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
		Path:      "venafi-policy/",
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
		Path:      "venafi-policy/default",
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
		Path:      "venafi-policy/",
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
		Path:      "venafi-policy/second",
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
		Path:      "venafi-policy/",
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
