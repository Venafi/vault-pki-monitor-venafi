package pki

import (
	"context"
	"crypto/tls"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/logical"
	"log"
	"math/rand"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestBackend_PathImportToTPP(t *testing.T) {
	rand := randSeq(5)
	domain := "example.com"

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

	// create a role entry
	roleData := map[string]interface{}{
		"allowed_domains":    domain,
		"allow_subdomains":   "true",
		"max_ttl":            "4h",
		"allow_bare_domains": true,
		"generate_lease":     true,
		"tpp_import":         true,
		"tpp_url":            os.Getenv("TPPURL"),
		"tpp_user":           os.Getenv("TPPUSER"),
		"tpp_password":       os.Getenv("TPPPASSWORD"),
		"zone":               os.Getenv("TPPZONE"),
		"trust_bundle_file":  os.Getenv("TRUST_BUNDLE"),
		"tpp_import_timeout": 2,
		"tpp_import_workers": 5,
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/test-import",
		Storage:   storage,
		Data:      roleData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create a role, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	// issue some certs
	//i := 1
	//for i < 10 {
	//	randCN := rand + "-import." + domain
	//	certData := map[string]interface{}{
	//		"common_name": randCN,
	//	}
	//	resp, err = b.HandleRequest(context.Background(), &logical.Request{
	//		Operation: logical.UpdateOperation,
	//		Path:      "issue/test-import",
	//		Storage:   storage,
	//		Data:      certData,
	//	})
	//	if resp != nil && resp.IsError() {
	//		t.Fatalf("failed to issue a cert, %#v", resp)
	//	}
	//	if err != nil {
	//		t.Fatal(err)
	//	}
	//
	//	i = i + 1
	//}

	// issue particular cert
	singleCN := rand + "-import." + domain
	certData := map[string]interface{}{
		"common_name": singleCN,
	}
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/test-import",
		Storage:   storage,
		Data:      certData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue a cert, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Second)

	//retrieve imported certificate
	//res.Certificates[0].CertificateRequestId != "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com"
	log.Println("Trying to retrieve requested certificate",singleCN)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	var tppConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       os.Getenv("TPPURL"),
		Credentials: &endpoint.Authentication{
			User:     os.Getenv("TPPUSER"),
			Password: os.Getenv("TPPPASSWORD")},
		Zone: os.Getenv("TPPZONE"),
	}

	req := &certificate.Request{}
	req.PickupID = "\\VED\\Policy\\devops\\vcert\\"+singleCN
	cl, err := vcert.NewClient(tppConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}
	cl.RetrieveCertificate(req)


	//list import queue
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "import-queue/",
		Storage:   storage,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list certs, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}
	keys := resp.Data["keys"]
	log.Printf("Import queue list is:\n %v", keys)
	time.Sleep(30 * time.Second)

}

func randSeq(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
