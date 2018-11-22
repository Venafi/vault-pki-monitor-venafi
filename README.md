# Vault PKI backend plugin with import to Venafi Platform

This is the original Hashicorp Vault PKI secrets engine (https://www.vaultproject.io/docs/secrets/pki/index.html) which can import signed certificates to the Venafi Platform.

## Quickstart

1. Read about the Hashicorp Vault plugin system https://www.vaultproject.io/docs/internals/plugins.html

1. From the command line download the plugin zip package for your OS and unzip it to bin/ folder
    ```
    wget https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/0.0.2/vault-pki-monitor-venafi_0.0.3_linux.zip && unzip vault-pki-monitor-venafi_0.0.3_linux.zip
    mv vault-pki-monitor-venafi bin/vault-pki-monitor-venafi
    ```

1. Configure your Hashicorp Vault to use plugin_directory where you download the plugin. Use vault-config.hcl from this repo as example.

1. Start your Vault. If you don't have working configuration you can start it in dev mode:
    ```
    echo 'plugin_directory = "bin"' > vault-config.hcl
    vault server -log-level=debug -dev -config=vault-config.hcl
    ```

[![demo](https://asciinema.org/a/VQ1f9Xdmftz5FhtX0GP1bblSg.png)](https://asciinema.org/a/VQ1f9Xdmftz5FhtX0GP1bblSg?autoplay=1)

1.  From the command line, export the VAULT_ADDR variable to fit local started client:
    `
    export VAULT_ADDR=http://127.0.0.1:8200
    `

1. Get the sha256 checksum of plugin binary:
    `
    SHA256=$(shasum -a 256 bin/vault-pki-monitor-venafi | cut -d' ' -f1)
    `

1. Add the plugin to the vault system catalog:
    `
    vault write sys/plugins/catalog/vault-pki-monitor-venafi sha_256="${SHA256}" command="vault-pki-monitor-venafi"
    `

1. Enable the plugin secret backend:
    `
    vault secrets enable -path=vault-pki-monitor-venafi -plugin-name=vault-pki-monitor-venafi plugin
    `

1. Create a PKI role (https://www.vaultproject.io/docs/secrets/pki/index.html). You will need to add following Venafi Platform options:


		tpp_import="true"
		tpp_url=<URL of Venafi Platform Example: https://venafi.example.com/vedsdk>
		tpp_user=<web API user for Venafi Platfrom Example: admin>
		tpp_password=<Password for web API user Example: password>
		zone=<Prepared Platform policy>

    Example:
    ```
    vault write vault-pki-monitor-venafi/roles/import \
    	tpp_import="true"  \
    	tpp_url=https://venafi.example.com/vedsdk \
    	tpp_user=admin \
    	tpp_password=password \
    	zone="vault\\prepared-policy" \
    	generate_lease=true store_by_cn="true" store_pkey="true" store_by_serial="true" ttl=1h max_ttl=1h \
    	allowed_domains=import.example.com \
    	allow_subdomains=true
    ```

1. Sign the PKI CA:
    ```
    vault write vault-pki-monitor-venafi/root/generate/internal \
            common_name=example.com \
            ttl=8760h
    ```

1. Sign the certificate and import it using standart PKI command. Example:

    ```
    vault write vault-pki-monitor-venafi/issue/import \
        common_name="import1.import.example.com" \
        alt_names="alt1.import.example.com,alt2-hbpxs.import.example.com"
    ```

1. Check the Vault log, you should see there something like this:
    ```
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: 2018/11/14 17:18:59 Job id: 1 ### Certificate imported:
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:  {
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateDN": "\\VED\\Policy\\devops\\vcert\\import-bt1ia.import.example.com",
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "CertificateVaultId": 9147083,
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi:     "Guid": "{dffb26c2-4510-4965-89c0-4d64a04b80fa}"
2018-11-14T17:18:59.586+0300 [DEBUG] secrets.plugin.plugin_84b4a95f.vault-pki-monitor-venafi.vault-pki-monitor-venafi: }
    ```

[![demo](https://asciinema.org/a/FrX6zj2MwbYLjop9ceIwUFNVU.png)](https://asciinema.org/a/FrX6zj2MwbYLjop9ceIwUFNVU?autoplay=1)

1. Lookup you certificate on the Venafi Platform

## Import trust chain for the Platform

If Venafi Platform uses an internal (self-signed) certificate, you must get your server root certificate.
Use the openssl command, below, and specify the PEM file name as the 'trust_bundle_file' parameter. Otherwise, the plugin will fail because of untrusted certificate error.
Use the following command to import the certificate to the chain.pem file.
The main.tf file is already configured to use this file as a trust bundle.

```bash
echo | openssl s_client -showcerts -servername TPP_ADDRESS -connect TPP_ADDRESS:TPP_PORT | openssl x509 -outform pem -out chain.pem
```

Example:

```bash
echo | openssl s_client -showcerts -servername venafi.example.com -connect venafi.example.com:5008 | openssl x509 -outform pem -out chain.pem
```

## Import queue
After the certificate is signed it is saved to the import queue. Import is automaticaly started after certificate is signed and will run in endless loop until plugin will exit.
You also can start import loop by running following command:
```
vault read vault-pki-monitor-venafi/import-queue/<rolename>
```

You can list certificate serial numbers that are present in the import quque using the following command :
```
vault list vault-pki-monitor-venafi/import-queue
```

## Options
To list the options, run:
```
vault path-help  vault-pki-monitor-venafi/roles/<ROLE_NAME>
```

Example:
```bash
vault path-help  vault-pki-monitor-venafi/roles/import
```

List of Venafi monitor specific options:

| Parameter          | Description | Default |
| ------------------ | ----------- | -------|
|`tpp_url`           |URL of Venafi Platfrom. Example: https://tpp.venafi.example/vedsdk||
|`zone`              |Name of Venafi Platfrom or Cloud policy.<br> Example for Platform: testpolicy\\vault <br> Example for Venafi Cloud: Default|`Default`|
|`tpp_user`          |web API user for Venafi Platform <br> Example: admin ||
|`tpp_password`      |Password for web API user <br> Example: password ||
|`tpp_import`        |Import certificate to Venafi Platform if true |`true`|
|`trust_bundle_file` |Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server. <br> Example: <br> `trust_bundle_file = "/full/path/to/chain.pem"` ||
|`tpp_import_timeout`|Timeout in second to rerun import queue |15|
|`tpp_import_workers`|Max amount of simultaneously working instances of vcert import |3|


## Quickstart for developers

1. Export your Venafi Platform configuration variables

    ```
    export TPPUSER=<web API user for Venafi Platfrom Example: admin>
    export TPPPASSWORD=<Password for web API user Example: password>
    export TPPURL=<URL of Venafi Platform Example: https://venafi.example.com/vedsdk>
    export TPPZONE=<Prepared Platform policy>
    ```

    Platform policy name could be tricky. If you have spaces enter policy in double quotes:
    ```
    export TPPZONE="My Policy"
    ```

    And if you have backslash (nested policy) you should enter four backslashes:
    ```
    export TPPZONE="first\\\\second"
    ```

2. Run `make dev_server` to start Vault server

3. Run `make dev` to build and enable plugin.

4. Run `make import` to sign random certificate and import it to the Platform.