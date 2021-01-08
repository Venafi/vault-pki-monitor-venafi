package pki

import (
	"context"
	"github.com/hashicorp/vault/api"
	logicaltest "github.com/hashicorp/vault/helper/testhelpers/logical"
	"github.com/hashicorp/vault/sdk/logical"
	"os"
	"testing"
)

const (
	logPrefixVenafiImport            = "VENAFI_IMPORT: "
	logPrefixVenafiPolicyEnforcement = "VENAFI_POLICY_ENFORCEMENT: "
	logPrefixVenafiRoleyDefaults     = "VENAFI_ROLE_DEFAULTS: "
	logPrefixVenafiScheduler         = "VENAFI_SCHEDULER: "
	logPrefixVenafiSecret            = "VENAFI_SECRET: "
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
	"tpp_url":               os.Getenv("TPP_URL"),
	"tpp_user":              os.Getenv("TPP_USER"),
	"tpp_password":          os.Getenv("TPP_PASSWORD"),
	"zone":                  os.Getenv("TPP_ZONE"),
	"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
	"auto_refresh_interval": 1,
	"venafi_secret":         venafiSecretDefaultName + "tpp",
}

var venafiTestTPPConfigNoRefresh = map[string]interface{}{
	"tpp_url":               os.Getenv("TPP_URL"),
	"tpp_user":              os.Getenv("TPP_USER"),
	"tpp_password":          os.Getenv("TPP_PASSWORD"),
	"zone":                  os.Getenv("TPP_ZONE"),
	"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
	"auto_refresh_interval": 0,
	"venafi_secret":         venafiSecretDefaultName + "tpp_noRefresh",
}

var venafiTestConfigBadData = map[string]interface{}{
	"cloud_url":     os.Getenv("CLOUD_URL"),
	"apikey":        os.Getenv("CLOUD_APIKEY"),
	"zone":          os.Getenv("CLOUD_ZONE_RESTRICTED"),
	"venafi_secret": venafiSecretDefaultName + "badData",
}

var venafiTestTPPConfigRestricted = map[string]interface{}{
	"tpp_url":               os.Getenv("TPP_URL"),
	"tpp_user":              os.Getenv("TPP_USER"),
	"tpp_password":          os.Getenv("TPP_PASSWORD"),
	"zone":                  os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
	"auto_refresh_interval": 1,
	"venafi_secret":         venafiSecretDefaultName + "tpp_restricted",
}

var venafiTestCloudConfigRestricted = map[string]interface{}{
	"cloud_url":             os.Getenv("CLOUD_URL"),
	"apikey":                os.Getenv("CLOUD_APIKEY"),
	"zone":                  os.Getenv("CLOUD_ZONE_RESTRICTED"),
	"auto_refresh_interval": 1,
	"venafi_secret":         venafiSecretDefaultName + "cloud_restricted",
}

var venafiTestTokenConfigRestricted = map[string]interface{}{
	"url":                   os.Getenv("TPP_TOKEN_URL"),
	"access_token":          os.Getenv("TPP_ACCESS_TOKEN"),
	"zone":                  os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file":     os.Getenv("TRUST_BUNDLE"),
	"auto_refresh_interval": 1,
	"venafi_secret":         venafiSecretDefaultName + "token_restricted",
}

var venafiTestCloudConfigAllAllow = map[string]interface{}{
	"cloud_url":             os.Getenv("CLOUD_URL"),
	"apikey":                os.Getenv("CLOUD_APIKEY"),
	"zone":                  os.Getenv("CLOUD_ZONE"),
	"auto_refresh_interval": 1,
	"venafi_secret":         venafiSecretDefaultName + "cloud",
}

var venafiTestTPPConfigImportOnlyNonCompliant = map[string]interface{}{
	"tpp_url":                   os.Getenv("TPP_URL"),
	"tpp_user":                  os.Getenv("TPP_USER"),
	"tpp_password":              os.Getenv("TPP_PASSWORD"),
	"zone":                      os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file":         os.Getenv("TRUST_BUNDLE"),
	"import_only_non_compliant": true,
	"auto_refresh_interval":     1,
	"venafi_secret":             venafiSecretDefaultName + "tpp",
}
var createVenafiSecretStep = logicaltest.TestStep{
	Operation: logical.UpdateOperation,
	Path:      venafiSecretPath + venafiTestTPPConfigAllAllow["venafi_secret"].(string),
	Data:      venafiTestTPPConfigAllAllow,
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
	policyData = copyMap(venafiTestCloudConfigRestricted)
	return
}

func makeVenafiTPPConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	policyData = copyMap(venafiTestTPPConfigRestricted)
	return
}

func makeVenafiTokenConfig() (domain string, policyData map[string]interface{}) {
	domain = "vfidev.com"
	policyData = copyMap(venafiTestTokenConfigRestricted)
	return
}

func writeVenafiSecret(b *backend, storage logical.Storage, secretData map[string]interface{}, t *testing.T, venafiSecretName string) *logical.Response {
	t.Log("Writing Venafi secret configuration")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiSecretPath + venafiSecretName,
		Storage:   storage,
		Data:      secretData,
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("failed to configure venafi secret, %#v", resp)
	}
	if err != nil {
		t.Fatal(err)
	}

	return resp
}

func writePolicy(b *backend, storage logical.Storage, policyData map[string]interface{}, t *testing.T, policyName string) *logical.Response {

	secretName := policyData["venafi_secret"].(string)
	if secretName == "" {
		t.Fatalf("failed to read Venafi Secret on policy %s. Looks like its empty", policyName)
	}

	writeVenafiSecret(b, storage, policyData, t, secretName)

	t.Log("Writing Venafi policy configuration")
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      venafiPolicyPath + policyName,
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
	venafiSecretName := venafiTestTPPConfigAllAllow["venafi_secret"].(string)
	_, err := client.Logical().Write(mountPoint+"/"+venafiSecretPath+venafiSecretName, venafiTestTPPConfigAllAllow)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write(mountPoint+"/"+venafiPolicyPath+defaultVenafiPolicyName, venafiTestTPPConfigAllAllow)
	if err != nil {
		t.Fatal(err)
	}
}

func checkRoleEntry(t *testing.T, haveRoleEntryData roleEntry, wantRoleEntryData roleEntry) {
	var want string
	var have string

	want = wantRoleEntryData.OU[0]
	have = haveRoleEntryData.OU[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = wantRoleEntryData.Organization[0]
	have = haveRoleEntryData.Organization[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = wantRoleEntryData.Country[0]
	have = haveRoleEntryData.Country[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = wantRoleEntryData.Locality[0]
	have = haveRoleEntryData.Locality[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	want = wantRoleEntryData.Province[0]
	have = haveRoleEntryData.Province[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}

	if !testEqStrginSlice(wantRoleEntryData.AllowedDomains, haveRoleEntryData.AllowedDomains) {
		t.Fatalf("%s doesn't match %s", wantRoleEntryData.AllowedDomains, haveRoleEntryData.AllowedDomains)
	}

	want = wantRoleEntryData.KeyUsage[0]
	have = haveRoleEntryData.KeyUsage[0]
	if have != want {
		t.Fatalf("%s doesn't match %s", have, want)
	}
}

func testEqStrginSlice(a, b []string) bool {

	// If one is nil, the other must also be nil.
	if (a == nil) != (b == nil) {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func sliceContains(slice []string, item string) bool {
	set := make(map[string]struct{}, len(slice))
	for _, s := range slice {
		set[s] = struct{}{}
	}

	_, ok := set[item]
	return ok
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	cp := make(map[string]interface{})
	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cp[k] = copyMap(vm)
		} else {
			cp[k] = v
		}
	}

	return cp
}
