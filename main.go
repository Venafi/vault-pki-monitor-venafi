package main

import (
	pki "github.com/Venafi/vault-pki-monitor-venafi/plugin/pki"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/plugin"
	"log"
	"os"
)

//Plugin config
//TODO: Transfer to normal logger
//Example:
//hclog "github.com/hashicorp/go-hclog"
//logger := hclog.New(&hclog.LoggerOptions{})

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	if err := flags.Parse(os.Args[1:]); err != nil {
		log.Fatal(err)
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: pki.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}
