package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/Venafi/vcert/pkg/verror"
	"github.com/hashicorp/vault/sdk/framework"
	hconsts "github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"strings"
	"sync"
	"time"
)

//Jobs tructure for import queue worker
type Job struct {
	id         int
	entry      string
	roleName   string
	policyName string
	importPath string
	ctx        context.Context
	//req        *logical.Request
	storage logical.Storage
}

// This returns the list of queued for import to TPP certificates
func pathImportQueue(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/" + framework.GenericNameRegex("role"),

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathUpdateImportQueue,
			//TODO: add delete operation to stop import queue and delete it
			//TODO: add delete operation to delete particular import record

		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	ret.Fields = addNonCACommonFields(map[string]*framework.FieldSchema{})
	return ret
}

func pathImportQueueList(b *backend) *framework.Path {
	ret := &framework.Path{
		Pattern: "import-queue/",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathFetchImportQueueList,
		},

		HelpSynopsis:    pathImportQueueSyn,
		HelpDescription: pathImportQueueDesc,
	}
	return ret
}

func (b *backend) pathFetchImportQueueList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roles, err := req.Storage.List(ctx, "import-queue/")
	var entries []string
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		log.Printf("%s Getting entry %s", logPrefixVenafiImport, role)
		rawEntry, err := req.Storage.List(ctx, "import-queue/"+role)
		if err != nil {
			return nil, err
		}
		var entry []string
		for _, e := range rawEntry {
			entry = append(entry, fmt.Sprintf("%s: %s", role, e))
		}
		entries = append(entries, entry...)
	}
	return logical.ListResponse(entries), nil
}

func (b *backend) pathUpdateImportQueue(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	roleName := data.Get("role").(string)
	log.Printf("%s Using role: %s", logPrefixVenafiImport, roleName)

	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) fillImportQueueTask(roleName string, policyName string, noOfWorkers int, storage logical.Storage, conf *logical.BackendConfig) {
	ctx := context.Background()
	jobs := make(chan Job, 100)
	replicationState := conf.System.ReplicationState()
	//Checking if we are on master or on the stanby Vault server
	isSlave := !(conf.System.LocalMount() || !replicationState.HasState(hconsts.ReplicationPerformanceSecondary)) ||
		replicationState.HasState(hconsts.ReplicationDRSecondary) ||
		replicationState.HasState(hconsts.ReplicationPerformanceStandby)
	if isSlave {
		log.Printf("%s We're on slave. Sleeping", logPrefixVenafiImport)
		return
	}
	log.Printf("%s We're on master. Starting to import certificates", logPrefixVenafiImport)
	//var err error
	importPath := "import-queue/" + roleName + "/"

	entries, err := storage.List(ctx, importPath)
	if err != nil {
		log.Printf("%s Could not get queue list from path %s: %s", logPrefixVenafiImport, err, importPath)
		return
	}
	log.Printf("%s Queue list on path %s has length %v", logPrefixVenafiImport, importPath, len(entries))

	var wg sync.WaitGroup
	wg.Add(noOfWorkers)
	for i := 0; i < noOfWorkers; i++ {
		go func() {
			defer func() {
				r := recover()
				if r != nil {
					log.Printf("%s recover %s", logPrefixVenafiImport, r)
				}
				wg.Done()
			}()
			for job := range jobs {
				result := b.processImportToTPP(job)
				log.Printf("%s Job id: %d ### Processed entry: %s , result:\n %v\n", logPrefixVenafiImport, job.id, job.entry, result)
			}
		}()
	}
	for i, entry := range entries {
		log.Printf("%s Allocating job for entry %s", logPrefixVenafiImport, entry)
		job := Job{
			id:         i,
			entry:      entry,
			importPath: importPath,
			roleName:   roleName,
			policyName: policyName,
			storage:    storage,
			ctx:        ctx,
		}
		jobs <- job
	}
	close(jobs)
	wg.Wait()
}

func (b *backend) importToTPP(storage logical.Storage, conf *logical.BackendConfig) {

	log.Printf("%s starting importcontroler", logPrefixVenafiImport)
	b.taskStorage.register("importcontroler", func() {
		b.controlImportQueue(storage, conf)
	}, 1, time.Second*1)
}

func (b *backend) controlImportQueue(storage logical.Storage, conf *logical.BackendConfig) {
	log.Printf("%s running control import queue", logPrefixVenafiImport)
	ctx := context.Background()
	const fillQueuePrefix = "fillqueue-"
	roles, err := storage.List(ctx, "role/")
	if err != nil {
		log.Printf("%s Couldn't get list of roles %s", logPrefixVenafiImport, roles)
		return
	}

	for i := range roles {
		roleName := roles[i]
		//Update role since it's settings may be changed
		role, err := b.getRole(ctx, storage, roleName)
		if err != nil {
			log.Printf("%s Error getting role %v: %s\n Exiting.", logPrefixVenafiImport, role, err)
			continue
		}

		if role.VenafiImportPolicy == "" {
			//no import policy defined for role. Skipping
			continue
		}
		if role == nil {
			log.Printf("%s Unknown role %v\n", logPrefixVenafiImport, role)
			continue
		}

		policyConfig, err := b.getVenafiPolicyConfig(ctx, storage, role.VenafiImportPolicy)
		if err != nil {
			log.Printf("%s Error getting policy %v: %s\n Exiting.", logPrefixVenafiImport, role.VenafiImportPolicy, err)
			continue
		}
		b.taskStorage.register(fillQueuePrefix+roleName, func() {
			log.Printf("%s run queue filler %s", logPrefixVenafiImport, roleName)
			b.fillImportQueueTask(roleName, role.VenafiImportPolicy, policyConfig.VenafiImportWorkers, storage, conf)
		}, 1, time.Duration(policyConfig.VenafiImportTimeout)*time.Second)

	}
	stringInSlice := func(s string, sl []string) bool {
		for i := range sl {
			if sl[i] == s {
				return true
			}
		}
		return false
	}
	for _, taskName := range b.taskStorage.getTasksNames() {
		if strings.HasPrefix(taskName, fillQueuePrefix) && !stringInSlice(strings.TrimPrefix(taskName, fillQueuePrefix), roles) {
			b.taskStorage.del(taskName)
		}
	}
}

func (b *backend) processImportToTPP(job Job) string {
	ctx := job.ctx
	//req := job.req
	storage := job.storage
	entry := job.entry
	id := job.id
	msg := fmt.Sprintf("Job id: %v ###", id)
	importPath := job.importPath
	log.Printf("%s %s Trying to import certificate with SN %s", logPrefixVenafiImport, msg, entry)
	cl, err := b.ClientVenafi(ctx, storage, job.policyName)
	if err != nil {
		return fmt.Sprintf("%s Could not create venafi client: %s", msg, err)
	}

	certEntry, err := storage.Get(ctx, importPath+entry)
	if err != nil {
		return fmt.Sprintf("%s Could not get certificate from %s: %s", msg, importPath+entry, err)
	}
	if certEntry == nil {
		return fmt.Sprintf("%s Could not get certificate from %s: cert entry not found", msg, importPath+entry)
	}
	block := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certEntry.Value,
	}

	Certificate, err := x509.ParseCertificate(certEntry.Value)
	if err != nil {
		return fmt.Sprintf("%s Could not get certificate from entry %s: %s", msg, importPath+entry, err)
	}
	//TODO: here we should check for existing CN and set it to DNS or throw error
	cn := Certificate.Subject.CommonName

	certString := string(pem.EncodeToMemory(&block))
	log.Printf("%s %s Importing cert to %s:\n", logPrefixVenafiImport, msg, cn)

	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      cn,
		CertificateData: certString,
		PrivateKeyData:  "",
		Password:        "",
		Reconcile:       false,
		CustomFields:    []certificate.CustomField{{Type: certificate.CustomFieldOrigin, Value: "HashiCorp Vault (+)"}},
	}
	importResp, err := cl.ImportCertificate(importReq)
	if err != nil {
		if errors.Is(err, verror.ServerBadDataResponce) || errors.Is(err, verror.UserDataError) {
			//TODO: Here should be renew instead of deletion
			b.deleteCertFromQueue(job)
		}
		return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)

	}
	log.Printf("%s %s Certificate imported:\n %s", logPrefixVenafiImport, msg, pp(importResp))
	b.deleteCertFromQueue(job)
	return pp(importResp)

}

func (b *backend) deleteCertFromQueue(job Job) {
	ctx := job.ctx
	s := job.storage
	entry := job.entry
	msg := fmt.Sprintf("Job id: %v ###", job.id)
	importPath := job.importPath
	log.Printf("%s %s Removing certificate from import path %s", logPrefixVenafiImport, msg, importPath+entry)
	err := s.Delete(ctx, importPath+entry)
	if err != nil {
		log.Printf("%s %s Could not delete %s from queue: %s", logPrefixVenafiImport, msg, importPath+entry, err)
	} else {
		log.Printf("%s %s Certificate with SN %s removed from queue", logPrefixVenafiImport, msg, entry)
		_, err := s.List(ctx, importPath)
		if err != nil {
			log.Printf("%s %s Could not get queue list: %s", logPrefixVenafiImport, msg, err)
		}
	}
}

func (b *backend) cleanupImportToTPP(roleName string, ctx context.Context, req *logical.Request) {

	importPath := "import-queue/" + roleName + "/"
	entries, err := req.Storage.List(ctx, importPath)
	if err != nil {
		log.Printf("%s Could not read from queue: %s", logPrefixVenafiImport, err)
	}
	for _, sn := range entries {
		err = req.Storage.Delete(ctx, importPath+sn)
		if err != nil {
			log.Printf("%s Could not delete %s from queue: %s", logPrefixVenafiImport, importPath+sn, err)
		} else {
			log.Printf("%s Deleted %s from queue", logPrefixVenafiImport, importPath+sn)
		}
	}

}

const pathImportQueueSyn = `
Fetch a CA, CRL, CA Chain, or non-revoked certificate.
`

const pathImportQueueDesc = `
This allows certificates to be fetched. If using the fetch/ prefix any non-revoked certificate can be fetched.

Using "ca" or "crl" as the value fetches the appropriate information in DER encoding. Add "/pem" to either to get PEM encoding.

Using "ca_chain" as the value fetches the certificate authority trust chain in PEM encoding.
`
