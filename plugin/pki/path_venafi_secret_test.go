package pki

import "testing"

func TestVenafiSecretValidate(t *testing.T) {
	entry := &venafiSecretEntry{}

	err := validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", errorTextInvalidMode, err)
	}

	entry = &venafiSecretEntry{
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextURLEmpty {
		t.Fatalf("Expecting error %s but got %s", errorTextURLEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TPPUser:     "admin",
		TPPPassword: "xxxx",
		Zone:        "zoneName",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextMixedTPPAndCloud {
		t.Fatalf("Expecting error %s but got %s", errorTextMixedTPPAndCloud, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		AccessToken: "foo123bar==",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Zone:        "zoneName",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != errorTextMixedTokenAndCloud {
		t.Fatalf("Expecting error %s but got %s", errorTextMixedTokenAndCloud, err)
	}
}
