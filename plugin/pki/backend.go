package pki

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a new Backend framework struct
func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"cert/*",
				"ca/pem",
				"ca_chain",
				"ca",
				"crl/pem",
				"crl",
			},

			LocalStorage: []string{
				"revoked/",
				"crl",
				"certs/",
			},

			Root: []string{
				"root",
				"root/sign-self-issued",
			},

			SealWrapStorage: []string{
				"config/ca_bundle",
				"venafi-policy",
			},
		},

		Paths: []*framework.Path{
			pathListRoles(&b),
			pathRoles(&b),
			pathGenerateRoot(&b),
			pathSignIntermediate(&b),
			pathSignSelfIssued(&b),
			pathDeleteRoot(&b),
			pathGenerateIntermediate(&b),
			pathSetSignedIntermediate(&b),
			pathConfigCA(&b),
			pathConfigCRL(&b),
			pathConfigURLs(&b),
			pathSignVerbatim(&b),
			pathSign(&b),
			pathIssue(&b),
			pathRotateCRL(&b),
			pathFetchCA(&b),
			pathFetchCAChain(&b),
			pathFetchCRL(&b),
			pathFetchCRLViaCertPath(&b),
			pathFetchValid(&b),
			pathFetchListCerts(&b),
			pathImportQueue(&b),
			pathImportQueueList(&b),
			pathVenafiPolicy(&b),
			pathVenafiPolicyContent(&b),
			pathVenafiPolicyList(&b),
			pathVenafiPolicyMap(&b),
			pathVenafiPolicySync(&b),
			pathRevoke(&b),
			pathTidy(&b),
			pathVenafiSecrets(&b),
			pathVenafiSecretsList(&b),
		},

		Secrets: []*framework.Secret{
			secretCerts(&b),
		},

		BackendType: logical.TypeLogical,
	}

	b.crlLifetime = time.Hour * 72
	b.tidyCASGuard = new(uint32)
	b.storage = conf.StorageView
	//Don't start import queue on tests which are using nil storage
	if b.storage == nil {
		log.Println("Can't start queue when storage is nil")
	} else {
		b.taskStorage.init()
		b.importToTPP(conf)
		b.syncRoleWithVenafiPolicyRegister(conf)
	}

	return &b
}

type backend struct {
	*framework.Backend

	storage           logical.Storage
	crlLifetime       time.Duration
	revokeStorageLock sync.RWMutex
	tidyCASGuard      *uint32
	taskStorage       taskStorageStruct
	mux sync.Mutex
}

const backendHelp = `
The PKI backend dynamically generates X509 server and client certificates.

After mounting this backend, configure the CA using the "pem_bundle" endpoint within
the "config/" path.
`
