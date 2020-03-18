package pki

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

type getRoleDataFunc func(string, int, int) map[string]interface{}

func getTPPRoleConfig(domain string, timeout, workers int) map[string]interface{} {
	return map[string]interface{}{
		"allowed_domains":       domain,
		"allow_subdomains":      "true",
		"max_ttl":               "4h",
		"allow_bare_domains":    true,
		"generate_lease":        true,
		"venafi_import":         true,
		"tpp_url":               os.Getenv("TPP_URL"),
		"tpp_user":              os.Getenv("TPP_USER"),
		"tpp_password":          os.Getenv("TPP_PASSWORD"),
		"zone":                  os.Getenv("TPP_ZONE"),
		"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
		"venafi_import_timeout": timeout,
		"venafi_import_workers": workers,
	}
}

func getCloudRoleConfig(domain string, timeout, workers int) map[string]interface{} {
	return map[string]interface{}{
		"allowed_domains":       domain,
		"allow_subdomains":      "true",
		"max_ttl":               "4h",
		"allow_bare_domains":    true,
		"generate_lease":        true,
		"venafi_import":         true,
		"apikey":                os.Getenv("CLOUD_APIKEY"),
		"cloud_url":             os.Getenv("CLOUD_URL"),
		"zone":                  os.Getenv("CLOUD_ZONE"),
		"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
		"venafi_import_timeout": timeout,
		"venafi_import_workers": workers,
		"organization":          "Venafi Inc.",
		"ou":                    "Integration",
		"locality":              "Salt Lake",
		"province":              "Utah",
		"country":               "US",
	}
}

type getConnectionFunc func(t *testing.T) endpoint.Connector

func getTPPConnection(t *testing.T) endpoint.Connector {
	var tppConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeTPP,
		BaseUrl:       os.Getenv("TPP_URL"),
		Credentials: &endpoint.Authentication{
			User:     os.Getenv("TPP_USER"),
			Password: os.Getenv("TPP_PASSWORD")},
		Zone:       os.Getenv("TPP_ZONE"),
		LogVerbose: true,
	}
	cl, err := vcert.NewClient(tppConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}
	return cl
}

func getCloudConnection(t *testing.T) endpoint.Connector {
	var tppConfig = &vcert.Config{
		ConnectorType: endpoint.ConnectorTypeCloud,
		BaseUrl:       os.Getenv("CLOUD_URL"),
		Credentials: &endpoint.Authentication{
			APIKey: os.Getenv("CLOUD_APIKEY"),
		},
		Zone:       os.Getenv("CLOUD_ZONE"),
		LogVerbose: true,
	}
	cl, err := vcert.NewClient(tppConfig)
	if err != nil {
		t.Fatalf("could not connect to endpoint: %s", err)
	}
	return cl
}

func calcThumbprint(cert string) string {
	p, _ := pem.Decode([]byte(cert))
	h := sha1.New()
	h.Write(p.Bytes)
	buf := h.Sum(nil)
	return strings.ToUpper(fmt.Sprintf("%x", buf))
}
func TestBackend_PathImportToTPP(t *testing.T) {
	testBackend_pathImport(t, getTPPRoleConfig, getTPPConnection, venafiTestTPPConfigAllAllow)
}
func TestBackend_PathImportToCloud(t *testing.T) {
	testBackend_pathImport(t, getCloudRoleConfig, getCloudConnection, venafiTestCloudConfigAllAllow)
}
func testBackend_pathImport(t *testing.T, getRoleData getRoleDataFunc, getConnection getConnectionFunc, policy map[string]interface{}) {
	rand := randSeq(9)
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

	writePolicy(b, storage, policy, t)

	// generate root
	rootData := map[string]interface{}{
		"common_name":  "ca.some.domain",
		"organization": "Venafi Inc.",
		"ou":           "Integration",
		"locality":     "Salt Lake",
		"province":     "Utah",
		"country":      "US",
		"ttl":          "6h",
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
	roleData := getRoleData(domain, 2, 2)

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
	//Wait until certificate will be imported
	time.Sleep(10 * time.Second)
	certText := resp.Data["certificate"].(string)
	thumbprint := calcThumbprint(certText)
	//retrieve imported certificate
	log.Println("Trying to retrieve requested certificate", singleCN)
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req := &certificate.Request{}
	req.Thumbprint = thumbprint
	req.ChainOption = certificate.ChainOptionIgnore

	cl := getConnection(t)
	pcc, err := cl.RetrieveCertificate(req)
	if err != nil {
		t.Fatalf("could not retrieve certificate using thumbprint %s: %s", req.Thumbprint, err)
	}
	//log.Printf("Got certificate\n:%s",pp(pcc.Certificate))
	block, _ := pem.Decode([]byte(pcc.Certificate))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Error parsing cert: %s", err)
	}
	if cert.Subject.CommonName != singleCN {
		t.Fatalf("incorrect subject common name: expected %v, got %v", cert.Subject.CommonName, singleCN)
	}

}

func TestBackend_PathImportToTPPTwice(t *testing.T) {
	rand := randSeq(9)
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

	writePolicy(b, storage, venafiTestTPPConfigAllAllow, t)

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
	roleData := getTPPRoleConfig(domain, 1, 2)

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

	// issue particular cert
	singleCN := rand + "twice-import." + domain
	certData := map[string]interface{}{
		"common_name": singleCN,
	}

	for i := 1; i <= 3; i++ {
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
		//Wait until certificate will be imported
		time.Sleep(5 * time.Second)

		//retrieve imported certificate
		//res.Certificates[0].CertificateRequestId != "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com"
		log.Println("Trying to retrieve requested certificate", singleCN)
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		req := &certificate.Request{}
		req.PickupID = "\\VED\\Policy\\devops\\vcert\\" + singleCN
		req.ChainOption = certificate.ChainOptionIgnore
		//req.Thumbprint = "111111"

		cl := getTPPConnection(t)
		if err != nil {
			t.Fatalf("could not connect to endpoint: %s", err)
		}
		pcc, err := cl.RetrieveCertificate(req)
		if err != nil {
			t.Fatalf("could not retrieve certificate using requestId %s: %s", req.PickupID, err)
		}
		//log.Printf("Got certificate\n:%s",pp(pcc.Certificate))
		block, _ := pem.Decode([]byte(pcc.Certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Error parsing cert: %s", err)
		}
		if cert.Subject.CommonName != singleCN {
			t.Fatalf("Incorrect subject common name: expected %v, got %v", cert.Subject.CommonName, singleCN)
		} else {
			log.Printf("Subject common name: expected %v, got %v", cert.Subject.CommonName, singleCN)
		}
	}
}

func TestBackend_PathImportToTPPMultipleCerts(t *testing.T) {
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

	writePolicy(b, storage, venafiTestTPPConfigAllAllow, t)

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

	var certs_list []string
	//Importing certs in multiple roles
	for i := 1; i <= 3; i++ {
		randRole := rand + strconv.Itoa(i) + "-role"
		log.Println("Creating certs for role", randRole)
		// create a role entry
		roleData := getTPPRoleConfig(domain, 2, 5)

		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      "roles/" + randRole,
			Storage:   storage,
			Data:      roleData,
		})
		if resp != nil && resp.IsError() {
			t.Fatalf("failed to create a role, %#v", resp)
		}
		if err != nil {
			t.Fatal(err)
		}

		//issue some certs

		for j := 1; j < 10; j++ {
			randCN := rand + strconv.Itoa(j) + "-import." + domain
			certs_list = append(certs_list, randCN)
			certData := map[string]interface{}{
				"common_name": randCN,
			}
			resp, err = b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "issue/" + randRole,
				Storage:   storage,
				Data:      certData,
			})
			if resp != nil && resp.IsError() {
				t.Fatalf("failed to issue a cert, %#v", resp)
			}
			if err != nil {
				t.Fatal(err)
			}
		}

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

	}

	time.Sleep(30 * time.Second)
	//After creating all certificates we need to check that they exist in TPP
	log.Println("Trying check all certificates from list", certs_list)
	for _, singleCN := range certs_list {
		//retrieve imported certificate
		//res.Certificates[0].CertificateRequestId != "\\VED\\Policy\\devops\\vcert\\renx3.venafi.example.com"
		log.Println("Trying to retrieve requested certificate", singleCN)
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

		req := &certificate.Request{}
		req.PickupID = "\\VED\\Policy\\devops\\vcert\\" + singleCN
		req.ChainOption = certificate.ChainOptionIgnore
		//req.Thumbprint = "111111"

		cl := getTPPConnection(t)
		if err != nil {
			t.Fatalf("could not connect to endpoint: %s", err)
		}
		pcc, err := cl.RetrieveCertificate(req)
		if err != nil {
			t.Fatalf("could not retrieve certificate using requestId %s: %s", req.PickupID, err)
		}
		//log.Printf("Got certificate\n:%s",pp(pcc.Certificate))
		block, _ := pem.Decode([]byte(pcc.Certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("Error parsing cert: %s", err)
		}
		if cert.Subject.CommonName != singleCN {
			t.Fatalf("Incorrect subject common name: expected %v, got %v", cert.Subject.CommonName, singleCN)
		} else {
			log.Printf("Subject common name: expected %v, got %v", cert.Subject.CommonName, singleCN)
		}
	}

}
