package pki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

//Jobs tructure for import queue worker
type Job struct {
	id         int
	entry      string
	roleName   string
	importPath string
	ctx        context.Context
	req        *logical.Request
}

//Result tructure for import queue worker
type Result struct {
	job    Job
	result string
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
		log.Printf("Getting entry %s", role)
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
	log.Printf("Using role: %s", roleName)
	//Running import queue in background
	ctx = context.Background()
	go b.importToTPP(roleName, ctx, req)

	entries, err := req.Storage.List(ctx, "import-queue/"+data.Get("role").(string)+"/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) importToTPP(roleName string, ctx context.Context, req *logical.Request) {

	var err error
	var importLocked bool

	lockPath := "import-queue-lock/" + roleName
	importPath := "import-queue/" + roleName + "/"

	log.Printf("Locking import mutex on backend to safely change data for import lock\n")
	err = func() (err error) {
		b.importQueue.Lock()
		defer log.Printf("Unlocking import mutex on backend\n")
		defer b.importQueue.Unlock()

		log.Printf("Getting import lock for path %s", lockPath)
		importLockEntry, err := req.Storage.Get(ctx, lockPath)
		if err != nil {
			log.Printf("Unable to get lock import for role %s:\n %s\n", roleName, err)
			return
		}

		if importLockEntry == nil || importLockEntry.Value == nil || len(importLockEntry.Value) == 0 {
			log.Println("Role lock is empty, assuming it is false")
			importLocked = false
		} else {
			il := string(importLockEntry.Value)
			log.Printf("Got from storage %s", il)
			importLocked, err = strconv.ParseBool(il)
			if err != nil {
				log.Printf("Unable to parse lock import %s to bool for role %s:\n %s\n", il, roleName, err)
				return
			}
		}

		if importLocked {
			log.Printf("Import queue for role %s is locked. Exiting", roleName)
			err = errors.New("Import locked")
			return
		}

		//Locking import for a role
		err = req.Storage.Put(ctx, &logical.StorageEntry{
			Key:   lockPath,
			Value: []byte("true"),
		})
		if err != nil {
			log.Printf("Unable to lock import queue: %s\n", err)
		}
		return
	}()
	if err != nil {
		return
	}

	log.Println("!!!!Starting new import routine!!!!")
	for {
		entries, err := req.Storage.List(ctx, importPath)
		if err != nil {
			log.Printf("Could not get queue list from path %s: %s", err, importPath)
			break
		}
		log.Printf("Queue list on path %s is: %s", importPath, entries)

		//Update role since it's settings may be changed
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			log.Printf("Error getting role %v: %s\n Exiting.", role, err)
			break
		}
		if role == nil {
			log.Printf("Unknown role %v\n Exiting for path %s.", role, importPath)
			break
		}

		noOfWorkers := role.TPPImportWorkers
		if len(entries) > 0 {
			log.Printf("Creating %d of jobs for %d workers.\n", len(entries), noOfWorkers)
			var jobs = make(chan Job, len(entries))
			var results = make(chan Result, len(entries))
			startTime := time.Now()
			go b.createWorkerPool(noOfWorkers, results, jobs)
			go allocate(jobs, entries, ctx, req, roleName, importPath)
			for result := range results {
				log.Printf("Job id: %d ### Processed entry: %s , result:\n %v\n", result.job.id, result.job.entry, result.result)
			}
			log.Printf("Total time taken %v seconds.\n", time.Now().Sub(startTime))
		}
		log.Println("Waiting for next turn")
		time.Sleep(time.Duration(role.TPPImportTimeout) * time.Second) //todo: maybe need to sub working time from prev line
	}
	log.Printf("Setting import lock to false on path %s\n", lockPath)
	err = req.Storage.Put(ctx, &logical.StorageEntry{
		Key:   lockPath,
		Value: []byte("false"),
	})
}

func (b *backend) createWorkerPool(noOfWorkers int, results chan Result, jobs chan Job) {
	var wg sync.WaitGroup
	for i := 0; i < noOfWorkers; i++ {
		wg.Add(1)
		go b.worker(&wg, results, jobs)
	}
	wg.Wait()
	close(results)
}

func (b *backend) worker(wg *sync.WaitGroup, results chan Result, jobs chan Job) {
	for job := range jobs {
		output := Result{job, b.processImportToTPP(job)}
		results <- output
	}
	wg.Done()
}

func allocate(jobs chan Job, entries []string, ctx context.Context, req *logical.Request, roleName string, importPath string) {
	for i, entry := range entries {
		log.Printf("Allocating job for entry %s", entry)
		job := Job{
			id:         i,
			entry:      entry,
			importPath: importPath,
			roleName:   roleName,
			req:        req,
			ctx:        ctx,
		}
		jobs <- job
	}
	close(jobs)
}

func (b *backend) processImportToTPP(job Job) string {
	ctx := job.ctx
	req := job.req
	roleName := job.roleName
	entry := job.entry
	id := job.id
	msg := fmt.Sprintf("Job id: %v ###", id)
	importPath := job.importPath
	log.Printf("%s Processing entry %s\n", msg, entry)
	log.Printf("%s Trying to import certificate with SN %s", msg, entry)
	cl, err := b.ClientVenafi(ctx, req.Storage, req, roleName)
	if err != nil {
		return fmt.Sprintf("%s Could not create venafi client: %s", msg, err)
	}

	certEntry, err := req.Storage.Get(ctx, importPath+entry)
	if err != nil {
		return fmt.Sprintf("%s Could not get certificate from %s: %s", msg, importPath+entry, err)
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
	log.Printf("%s Importing cert to %s:\n %s", msg, cn, certString)

	importReq := &certificate.ImportRequest{
		// if PolicyDN is empty, it is taken from cfg.Zone
		ObjectName:      cn,
		CertificateData: certString,
		PrivateKeyData:  "",
		Password:        "",
		Reconcile:       false,
	}
	importResp, err := cl.ImportCertificate(importReq)
	if err != nil {
		if strings.Contains(string(err.Error()), "Import error. The certificate already exists at Certificate DN") {
			//TODO: Here should be renew instead of deletion
			b.deleteCertFromQueue(job)
		}
		return fmt.Sprintf("%s could not import certificate: %s\n", msg, err)

	}
	log.Printf("%s Certificate imported:\n %s", msg, pp(importResp))
	b.deleteCertFromQueue(job)
	return pp(importResp)

}

func (b *backend) deleteCertFromQueue(job Job) {
	ctx := job.ctx
	req := job.req
	entry := job.entry
	msg := fmt.Sprintf("Job id: %v ###", job.id)
	importPath := job.importPath
	log.Printf("%s Removing certificate from import path %s", msg, importPath+entry)
	err := req.Storage.Delete(ctx, importPath+entry)
	if err != nil {
		log.Printf("%s Could not delete %s from queue: %s", msg, importPath+entry, err)
	} else {
		log.Printf("%s Certificate with SN %s removed from queue", msg, entry)
		entries, err := req.Storage.List(ctx, importPath)
		if err != nil {
			log.Printf("%s Could not get queue list: %s", msg, err)
		} else {
			log.Printf("%s Queue for path %s is:\n %s", msg, importPath, entries)
		}
	}
}

func (b *backend) cleanupImportToTPP(roleName string, ctx context.Context, req *logical.Request) {

	importPath := "import-queue/" + roleName + "/"
	entries, err := req.Storage.List(ctx, importPath)
	for _, sn := range entries {
		err = req.Storage.Delete(ctx, importPath+sn)
		if err != nil {
			log.Printf("Could not delete %s from queue: %s", importPath+sn, err)
		} else {
			log.Printf("Deleted %s from queue", importPath+sn)
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
