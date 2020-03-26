package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"testing"
)

func TestSyncRoleWithPolicy(t *testing.T) {
	// create the backend
	config := logical.TestBackendConfig()
	storage := &logical.InmemStorage{}
	config.StorageView = storage

	b := Backend(config)
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}


	ctx := context.Background()
	req := &logical.Request{
		Storage:   storage,
	}
    err = b.roleVenafiSync(ctx,req)
	if err != nil {
		t.Fatal(err)
	}
}
