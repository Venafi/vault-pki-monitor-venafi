package pki

import (
	"context"
	"github.com/hashicorp/vault/api"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"os"
	"strings"
	"testing"
)

const msg_denied_by_policy = "certificate issue should be denied by policy, %#v"
const wrong_csr = `-----BEGIN CERTIFICATE REQUEST-----
MIIFSjCCAzICAQAwgaQxCzAJBgNVBAYTAldDMQ0wCwYDVQQIDARVdGFoMRcwFQYD
VQQHDA5Xcm9uZyBMb2NhbGl0eTESMBAGA1UECgwJV3JvbmcgT3JnMRMwEQYDVQQL
DApXcm9uZyBVbml0MR4wHAYJKoZIhvcNAQkBFg9lbWFpbEB3cm9uZy5jb20xJDAi
BgNVBAMMG3Rlc3QtY3NyLTMyMzEzMTMxLndyb25nLmNvbTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBALuwFXjQk0BY2z35uS7rp+tpznZS2oyY1HZC2ZXb
w8vIp9UOoYa9+919Gl+28Zr1K0ClW/4VY4h/p93HxuaJ0Emg9PlF2qHvwbR+uY1/
nY+0NK1deNy4xB1D0RQ9zMULzYhFXRE0ryrcEFVmad75tPQcvn+s61G4itY28uVu
d+7IKkMBvf1t2516dwrD9mMP5lUZQaLgeMvBWh/dDt94Ag/MIcHo7ceOTuMe10II
tqzBz6/qcCYt2glKoJFsmDomR3x/29451nF7orIFafg3dXum8LQy26XG9j8fcUUz
DxQHPp40k8Oc2pHuqKo7cCu9Oql4P+F9EGng1dJwMmVOQbuUj0OdqkVHwygabx/w
3WfBZqdFYbkvOFYJiMC3b+7GsWPvqf9/eA+l4Vnq/8LwUQbKdt23k7MDzw75uqO/
sntkBw9XgQeny6p4s7b0lLiFmyKwiKScws/dwdQ5s6y+H7u6lQNfsicDitTPMP20
EQ3nnjM9ENfEhDl7Muhyb+DAb7Vs1rARc6BOclwxYUDMNOErRBqedRCrj1nchOxy
HM4Nz/Csn+PhHyoOFuCGdc0lrvegjNF/inVYlicyzqH6WUlnNUg4k2nrhPJwUo79
FKsJ/UEsNvrxSr5L7kX6l/F6DKLHXX5kVEFD/83mTTOKw8AWTw96ASEX7J3AmY7C
8f/PAgMBAAGgYDBeBgkqhkiG9w0BCQ4xUTBPME0GA1UdEQRGMESCIGFsdDEtdGVz
dC1jc3ItMzIzMTMxMzEud3JvbmcuY29tgiBhbHQyLXRlc3QtY3NyLTMyMzEzMTMx
Lndyb25nLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAnVM3zi+Zeknpg3R/XTyVYdpX
31EA0aDg7SVm6iSIyD1iITPJQ1fGDY3/GaRUdD5TLzmyOohFS4dj2FV2zRi9BzfU
xqgy5zONGtXxzefiDCicc1aP2eduiQ/Gg1NSMopOYK5ppKfPHqSp+k4O3oYpn3oS
lkox7dez84gw3TdA68EFizE7JbwRV6CCit4EY1ZHM/tzhBogmr9yDxdNlNd1zzTL
tWMRU2vOVubbGCScapJehTIc+aOchNGrxDazmRwVuVFIE4Mw+9ALJJ3rJvGqZ6XF
5Fk0TVSuOTto4m0WHUAh+VeyfV4ZZEHwRtCv0y7e7mp7ZHiFKHsGUT2Ll7Ssp2o+
gdvwXrPsWhkbvuO9CQuh75BRCDqgBO4eVzIZ5DBur5/H8Nl6y9M44Mh2LRR/FYr5
pSyelv3jpGOuIq4obNch2yYLDwftEm7KuQI4YUpsZFZXeMUmvKop1rVBqLejcotK
NwnkGHoG3xeCk3x01af09B7YJfMnV/HCh3k5gf8XGgdpfNg4MjsrYRdFQ/fNTiv1
b7/jDBHlXox4Nxptg2aASDJR3iFfMdBju548SAeD984lq/lXcjII2yL6h8VkCQpd
kBLCbOylNnLu/CGd907fpBpWQ6rptGLnVEAs2ab02mcD0Ul4iVA4lXoLlj39JGyB
lICcWSA1Gqz34IAXJco=
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

const allowed_empty_csr = `-----BEGIN CERTIFICATE REQUEST-----
MIIEyTCCArECAQAwgYMxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRIwEAYD
VQQHDAlTYWx0IExha2UxFDASBgNVBAoMC1ZlbmFmaSBJbmMuMRQwEgYDVQQLDAtJ
bnRlZ3JhdGlvbjElMCMGA1UEAwwcdGVzdC1jc3ItMzIzMTMxMzEudmZpZGV2LmNv
bTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALsSuhL/AGryMUO+jrtM
xYfp2vUlgIKu/uGfm+4ILGrtWlH/i5+aoT3I+blUPskDDMLhvG4lD4xT9urxcnJj
2sO8hOPnSsTvMnAOLgi8OW2JMeeA74BsPi2lxXvW/392EAxPjxuMKULI0gm60vBi
yFtS6wRinvEUDkSy8r8Z0a0zsqsRKt9VMgJy2tEmRYMT0xkfC8GkARhgKNCe7kHJ
OjCS6MZgJSHekZBxKsLjblQFrHSCT0SrWJDLlHIwd9CL0uVkqe9UMfJ8Nm7WowXe
BrDUHNSOUjZo8jjqCSnu9vVw/MR4paMssSKcyXSKQcsUJQBfoWBMGTCUZolA86TM
U7DMxPorXm94ZfHiOa6qS5A20Z7VUvCp8BR3RF0b/5ntJwGULbMg5QBAZ6sF+rnm
BN5xAyrGHYck2TqphyZRAFRs/yuVdQx+3wHykAqzzX7cYlzI3EhT/3yQu5VZNclq
wxvCsT197s2VB8tcPxvAlBddKkLVY+hp4U5dxEDLxOf5+oryGx+6nOZdWlYKxxNZ
7P83oOjp95+UCVeDGDwI7+8y7OwK8AF82HqbeDm6dliKNQ4tnN1ddzWabXfuzuYl
OmdTiKDNR/gHUq2HaxekKHs39ToXyJg65+g3baEX5JM6KKmrXL2N8s6YiMMaF13m
3SPa3pzGKNNLYcqdkEjRjlKBAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAgEAJ4RK
9RrnI7AblRCYG5Rnyu/YvVkSu7gnp+04DeECntxv9FyP99aPgGPxlMzH11QFUwKZ
Kn4XLz8559JGA8umcWT559hQ4XFpYoyzEvnf/vdA9NAmSr0ssMsoZ1DjR4l0rR2m
Y+doP4CAqRh1rC6JDTMvo/WxwJRImgrnziyOwZba7mwDRNVIXWa70cFPfgb3fKro
egPkp/Hqvho0Rvu3m3o5Y35UxKiMylZUX3pHdpKXVG2wxj0FgeOepd4cFSHrF85q
uPhc12CDvv71wtxMcL8mmWizjpuGGBvDx0Tz8uJmaumNkIwZ+GGhqBsAPJI/YCy6
44WYs9vRDCjHnIXIazJTc3kFwaDOJF3btCYQ6dG1dHh8lRLnfkYLOtKlJ2gbrUqB
s44QoRhU5ZYUD1+8TYNWQtgceGjCTACsbxH4JKOG38NT4C/mv3ZsEC1yTfjxWRDH
CqLGi3SbYFiUEk0WRWAbwe80HtcAVCFCa2G3C/FGS/qCiFIbE9op5Ab3NDWJGdSI
gT230FFz4jsyW4395IiZ8UOoLXxBmnL382+hdB08aEdm4j/ZFeeButG0qb3XhUu3
/atUO1Boht8DNna1DH/1uLW0ovAAKgX+v3LTi/vadErW/X3S7P/ZnbLY5pA7nEBg
bOcvXbCN3l5HIY76e+6FbLGGCvNKcgNpSAAPYJg=
-----END CERTIFICATE REQUEST-----
`

var venafiTestTPPConfigAllAllow = map[string]interface{}{
	"tpp_url":           os.Getenv("TPPURL"),
	"tpp_user":          os.Getenv("TPPUSER"),
	"tpp_password":      os.Getenv("TPPPASSWORD"),
	"zone":              os.Getenv("TPPALLALLOWZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestTPPConfigRestricted = map[string]interface{}{
	"tpp_url":           os.Getenv("TPPURL"),
	"tpp_user":          os.Getenv("TPPUSER"),
	"tpp_password":      os.Getenv("TPPPASSWORD"),
	"zone":              os.Getenv("TPPRESTRICTEDZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestCloudConfigRestricted = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUDURL"),
	"apikey":    os.Getenv("CLOUDAPIKEY"),
	"zone":      os.Getenv("CLOUDRESTRICTEDZONE"),
}
var venafiTestCloudConfigAllAllow = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUDURL"),
	"apikey":    os.Getenv("CLOUDAPIKEY"),
	"zone":      os.Getenv("CLOUDZONE"),
}

var venafiTPPCreateSimplePolicyStep = logicaltest.TestStep{
	Operation: logical.UpdateOperation,
	Path:      venafiPolicyPath + defaultVenafiPolicyName,
	Data:      venafiTestTPPConfigAllAllow,
}
var venafiCloudCreateSimplePolicyStep = logicaltest.TestStep{
	Operation: logical.UpdateOperation,
	Path:      venafiPolicyPath + defaultVenafiPolicyName,
	Data:      venafiTestCloudConfigAllAllow,
}

func makeVenafiCloudConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	policyData = venafiTestCloudConfigRestricted
	return
}

func makeVenafiTPPConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	policyData = venafiTestTPPConfigRestricted
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
	_, err := client.Logical().Write(mountPoint+"/"+venafiPolicyPath+defaultVenafiPolicyName, venafiTestTPPConfigAllAllow)
	if err != nil {
		t.Fatal(err)
	}
}

//TODO: add test with empty organization
//TODO: add test for CA with emoty organization
//TODO: add test for CA with SANs
func venafiPolicyTests(t *testing.T, policyData map[string]interface{}, domain string) {
	// create the backend
	rand := randSeq(9)
	b, storage := createBackendWithStorage(t)
	writePolicy(b, storage, policyData, t)

	log.Println("Setting up role")
	roleData := map[string]interface{}{
		"organization":       "Venafi Inc.",
		"ou":                 "Integration",
		"locality":           "Salt Lake",
		"province":           "Utah",
		"country":            "US",
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

	log.Println("issue proper cert with empty SAN")
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

	log.Println("issue proper cert with SANs")
	singleCN = rand + "-policy." + domain
	certData = map[string]interface{}{
		"common_name": singleCN,
		"alt_names":   "foo." + domain + ",bar." + domain,
		"ip_sans":     "1.2.3.4",
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

	log.Println("Testing proper CSR without alt names")
	certData = map[string]interface{}{
		"csr": allowed_empty_csr,
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
