package main

import (
	pki "github.com/Venafi/vault-pki-monitor-venafi/plugin/pki"
	"github.com/hashicorp/vault/helper/pluginutil"
	"github.com/hashicorp/vault/logical/plugin"
	"log"
	"os"
)

//Plugin config
//TODO: Transfer to normal logger
//Example:
//hclog "github.com/hashicorp/go-hclog"
//logger := hclog.New(&hclog.LoggerOptions{})

func main() {
	apiClientMeta := &pluginutil.APIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := pluginutil.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: pki.Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}
