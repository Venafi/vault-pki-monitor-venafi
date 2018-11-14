package pki

import (
	"crypto/x509"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
)

//TODO: req.Sotrage is nill, we must configure it or will get nil pointer dereference
func TestBackend_ImportToTPP(t *testing.T) {
	rand := randSeq(5)
	domain := "example.com"
	randCN := rand + "-import." + domain

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "60h",
		},
	})

	resp, err := client.Logical().Write("pki/root/generate/internal", map[string]interface{}{
		"ttl":         "40h",
		"common_name": "my-website.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	caSerial := resp.Data["serial_number"]

	_, err = client.Logical().Write("pki/roles/import", map[string]interface{}{
		"allow_bare_domains": true,
		"allow_subdomains":   true,
		"allowed_domains":    domain,
		"generate_lease":     true,
		"tpp_import":         "true",
		"tpp_url":            os.Getenv("TPPURL"),
		"tpp_user":           os.Getenv("TPPUSER"),
		"tpp_password":       os.Getenv("TPPPASSWORD"),
		"zone":               os.Getenv("TPPZONE"),
		"trust_bundle_file":  os.Getenv("TRUST_BUNDLE"),
		"tpp_import_timeout": 15,
	})
	if err != nil {
		t.Fatal(err)
	}

	var serials = make(map[int]string)
	for i := 0; i < 6; i++ {
		resp, err := client.Logical().Write("pki/issue/import", map[string]interface{}{
			"common_name": randCN,
		})
		if err != nil {
			t.Fatal(err)
		}
		serials[i] = resp.Data["serial_number"].(string)
	}

	test := func(num int) {
		resp, err := client.Logical().Read("pki/cert/crl")
		if err != nil {
			t.Fatal(err)
		}
		crlPem := resp.Data["certificate"].(string)
		certList, err := x509.ParseCRL([]byte(crlPem))
		if err != nil {
			t.Fatal(err)
		}
		lenList := len(certList.TBSCertList.RevokedCertificates)
		if lenList != num {
			t.Fatalf("expected %d, found %d", num, lenList)
		}
	}

	revoke := func(num int) {
		resp, err = client.Logical().Write("pki/revoke", map[string]interface{}{
			"serial_number": serials[num],
		})
		if err != nil {
			t.Fatal(err)
		}

		resp, err = client.Logical().Write("pki/revoke", map[string]interface{}{
			"serial_number": caSerial,
		})
		if err == nil {
			t.Fatal("expected error")
		}
	}

	toggle := func(disabled bool) {
		_, err = client.Logical().Write("pki/config/crl", map[string]interface{}{
			"disable": disabled,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	test(0)
	revoke(0)
	revoke(1)
	test(2)
	toggle(true)
	test(0)
	revoke(2)
	revoke(3)
	test(0)
	toggle(false)
	test(4)
	revoke(4)
	revoke(5)
	test(6)
	toggle(true)
	test(0)
	toggle(false)
	test(6)
	time.Sleep(60 * time.Second)
}

func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
