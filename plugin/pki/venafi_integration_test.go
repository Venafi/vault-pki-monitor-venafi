package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAllVenafiIntegrations(t *testing.T) {
	/*
		Scenario:
		Create multiple random roles
		Create two policies for TPP
		Create two policies for Cloud
		Check policy enforecment sync
		Check policy default sync
		Check certificate import
		Check certificate signing
		Stress test
	*/
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

	writePolicy(b, storage, venafiTestTPPConfigAllAllow, t, defaultVenafiPolicyName)

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
	var randRoles []string

	for i := 1; i <= 3; i++ {
		r := rand + strconv.Itoa(i) + "-role"
		randRoles = append(randRoles, r)
	}
	for _, randRole := range randRoles {

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
	}

	//add created roles to policy
	venafiTestTPPConfigAllAllow[policyFieldImportRoles] = strings.Join(randRoles, ",")
	writePolicy(b, storage, venafiTestTPPConfigAllAllow, t, defaultVenafiPolicyName)

	for _, randRole := range randRoles {
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
