![Venafi](Venafi_logo.png)
[![MPL 2.0 License](https://img.shields.io/badge/License-MPL%202.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
![Community Supported](https://img.shields.io/badge/Support%20Level-Community-brightgreen)
![Compatible with TPP 18.2+ & Cloud](https://img.shields.io/badge/Compatibility-TPP%2018.2+%20%26%20Cloud-f9a90c)  
_This open source project is community-supported. To report a problem or share an idea, use the
**[Issues](../../issues)** tab; and if you have a suggestion for fixing the issue, please include those details, too.
In addition, use the **[Pull requests](../../pulls)** tab to contribute actual bug fixes or proposed enhancements.
We welcome and appreciate all contributions._

# Venafi PKI Monitoring Secrets Engine for HashiCorp Vault

This solution allows [HashiCorp Vault](https://www.vaultproject.io/) users to provide their
Information Security organization visibility into certificate issuance.
Vault issued certificates are automatically forwarded to the 
[Venafi Platform](https://www.venafi.com/platform/trust-protection-platform) or the [Venafi Cloud for DevOps](https://www.venafi.com/platform/cloud/devops) service which enables
risk assessment, incident response, and auditing that ensures compliance with enterprise security policy.
The [secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html) component was sourced from the
original HashiCorp Vault PKI secrets engine.

## Dependencies

* HashiCorp Vault: https://www.vaultproject.io/downloads.html

## Requirements for use with Trust Protection Platform

1. For policy enforcement, the Venafi WebSDK user that Vault will be using needs to have been granted view and read
   permissions to the policy folder from which Venafi policy will be obtained.
1. For issuance visibility, the Venafi WebSDK user that Vault will be using needs to have been granted write and create
   permission to the policy folder where Vault issued certificates will be imported, and the 
   _Allow Users to Import Duplicate Certificates and Reuse Private Keys_ policy of that folder needs to be set to 'Yes'
   to ensure that all certificates issued by the Vault can be imported.

### Trust between Vault and Trust Protection Platform

The Trust Protection Platform REST API (WebSDK) must be secured with a
certificate. Generally, the certificate is issued by a CA that is not publicly
trusted so establishing trust is a critical part of your setup.

Two methods can be used to establish trust. Both require the trust anchor
(root CA certificate) of the WebSDK certificate. If you have administrative
access, you can import the root certificate into the trust store for your
operating system. If you don't have administrative access, or prefer not to
make changes to your system configuration, save the root certificate to a file
in PEM format (e.g. /opt/venafi/bundle.pem) and reference it using the
`trust_bundle_file` parameter whenever you create or update a PKI role in your
Vault.

## Setup

This plugin was originally sourced from the
[built-in Vault PKI secrets engine](https://www.vaultproject.io/docs/secrets/pki/index.html)
and enhanced with features for integrating with Venafi Platform and Cloud.

1. Create the [directory](https://www.vaultproject.io/docs/internals/plugins#plugin-directory)
   where your Vault server will look for plugins (e.g. /etc/vault/vault_plugins).
   The directory must not be a symbolic link. On macOS, for example, /etc is a
   link to /private/etc. To avoid errors, choose an alternative directory such
   as /private/etc/vault/vault_plugins.

1. Download the latest `vault-pki-monitor-venafi` [release package](../../releases/latest) for your operating system. There are two versions, optional and script. The "optional" version allows certificates to be issues by the Vault CA when thre is no Venafi policy applied whereas the "strict" version will return an error.
Note that the URL for the zip file, referenced below, changes as new versions of the plugin are released.

    ```text
    $ wget -q https://github.com/Venafi/vault-pki-monitor-venafi/releases/download/v0.0.1/vault-pki-monitor-venafi_v0.0.1+1_linux_strict.zip
    ```

1. Compare the checksum of the package to the listed value on the GitHub release page.

    ```text
    $ sha256sum vault-pki-monitor-venafi_v0.0.1+1_linux_strict.zip
    ```

1. Unzip the binary to the plugin directory.

    ```text
    $ unzip vault-pki-monitor-venafi_v0.0.1+1_linux_strict.zip
    $ mv vault-pki-monitor-venafi_strict /etc/vault/vault_plugins
    ```

1. Update the Vault [server configuration](https://www.vaultproject.io/docs/configuration/) to specify the plugin directory:

    ```text
   plugin_directory = "/etc/vault/vault_plugins"
   ```

   :pushpin: **NOTE**: If plugin directory is a symbolic link, Vault responds
   with an error[:bookmark:](https://groups.google.com/forum/#!topic/vault-tool/IVYLA3aH72M).
   If you're configuring on a MacBook, /etc is default symlinked to /private/etc. To
   prevent the error from occurring, change the `plugin_directory` to a non-symlinked
   directory. For example "/private/etc/vault/vault_plugins". If you make this change,
   keep it in mind as you go through the remaining steps.

1. Start your vault using the [server command](https://www.vaultproject.io/docs/commands/server).

1. Get the SHA-256 checksum of the `vault-pki-monitor-venafi` plugin binary: 

    ```text
    $ SHA256=$(sha256sum /etc/vault/vault_plugins/vault-pki-monitor-venafi_strict |cut -d' ' -f1)
    ```

1. Register the `vault-pki-monitor-venafi` plugin in the Vault 
   [system catalog](https://www.vaultproject.io/docs/internals/plugins#plugin-catalog):

   ```
   $ vault write sys/plugins/catalog/secret/vault-pki-monitor-venafi_strict \
       sha_256="${SHA256}" command="vault-pki-monitor-venafi_strict"

   Success! Data written to: sys/plugins/catalog/secret/vault-pki-monitor-venafi_strict
   ```

   :pushpin: **NOTE**: If you get an error that says "can not execute files
    outside of configured plugin directory", it's probably because you didn't set the
    plugin directory correctly with a non-symlinked directory as mentioned earlier. Also,
    make sure this change is reflected when calling for the SHA-256 checksum.

1. Enable the secrets engine for the `vault-pki-monitor-venafi` plugin:

   ```text
   $ vault secrets enable -path=pki -plugin-name=vault-pki-monitor-venafi_strict plugin

   Success! Enabled the vault-pki-monitor-venafi_strict secrets engine at: pki/
   ```

1. Configure a Venafi secret that maps a name in Vault to connection and authentication settings for enrolling certificates using Venafi. The zone is a policy folder for Trust Protection Platform or a DevOps project zone for Venafi Cloud. Obtain the `access_token` and `refresh_token` for Trust Protection Platform using the [VCert CLI](https://github.com/Venafi/vcert/blob/master/README-CLI-PLATFORM.md#obtaining-an-authorization-token) (`getcred` action with `--client-id "hashicorp-vault-monitor-by-venafi"` and `--scope "certificate:manage,discover"`) or the Platform's Authorize REST API method. 

    **Trust Protection Platform**:

    ```
    $ vault write pki/venafi-policy/default \
        zone="DevOps\\Default" \
        url="https://tpp.example.com" trust_bundle_file="/path/to/bundle.pem" \
        access_token="tn1PwE1QTZorXmvnTowSyA==" refresh_token="MGxV7DzNnclQi9CkJMCXCg=="
   ```

   :pushpin: **NOTE**: Supplying a `refresh_token` allows the secrets engine to
   automatically obtain new tokens and operate without interruption whenever the
   `access_token` expires. This behavior is important to understand because it 
   may require you to provide a new `access_token` and `refresh_token` if you need
   to modify the Venafi secret in the future (i.e. depending upon whether the
   original set of tokens has been refreshed by the secrets engine plugin).

   **Venafi Cloud**:

    ```
    $ vault write pki/venafi/policy-default \ 
        apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
        zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    ```

    Following options are supported (note: this list can also be viewed from the command line using `vault path-help pki/venafi-policy/default`):

    | Parameter             | Type   | Description                                                                         | Example   |
   | --------------------- | ------ | ----------------------------------------------------------------------------------- | --------- |
   |`access_token`         |string  | Trust Protection Platform access token for the "hashicorp-vault-monitor-by-venafi" API Application |`tn1PwE1QTZorXmvnTowSyA==`|
   |`apikey`               |string  | Venafi Cloud API key                                                                |`142231b7-cvb0-412e-886b-6aeght0bc93d`|
   |`auto_refresh_interval`|int     | Interval of Venafi policy update in seconds. Set to 0 to disable automatic refresh  | 0 | 
   |`defaults_roles`       |string  | List of roles where default values from Venafi will be applied                      |`tpp`|
   |`enforcement_roles`    |string  | List of roles where Venafi policy enforcement is enabled                            |`tpp`|
   |`ext_key_usage`        |string  | A comma-separated string of allowed extended key usages                             |`ServerAuth,ClientAuth`|
   |`import_roles`         |string  | List of roles where issued certificates will be imported into the Venafi `zone`     |`tpp`|
   |`import_timeout`       |int     | Maximum wait in seconds before re-attempting certificate import from queue          | 15 |
   |`import_workers`       |int     | Maximum number of concurrent threads to use for VCert import                        | 5 |
   |`name`                 |string  | Name of the venafi-policy to apply to roles                                         |`another-policy`|
   |`url`                  |string  | Venafi service URL, generally only applicable to Trust Protection Platform          |`https://tpp.venafi.example`|
   |`refresh_token`        |string  | Refresh Token for Venafi Platform.                                                  |`MGxV7DzNnclQi9CkJMCXCg==`|
   |`tpp_password`         |string  | **[DEPRECATED]** Trust Protection Platform WebSDK password, use `access_token` if possible |`somePassword?`|
   |`tpp_user`             |string  | **[DEPRECATED]** Trust Protection Platform WebSDK username, use `access_token` if possible |`admin`|
   |`trust_bundle_file`    |string  | Text file containing trust anchor certificates in PEM format, generally required for Trust Protection Platform |`"/path/to/chain.pem"`|
   |`zone`                 |string   | Trust Protection Platform policy folder or Venafi Cloud zone ID (shown in Venafi Cloud UI) |`testpolicy\\vault`|

3. Configure a [role](https://www.vaultproject.io/api-docs/secret/pki#create-update-role) with which you want to use for enforcement policy.

    ```text
    $ vault write pki/roles/venafi-role generate_lease=true ttl=1h max_ttl=1h allow_any_name=true
    ```
4. Update the policy and add the created role to the defaults and enforcement lists.

    **Trust Protection Platform**:

    ```text 
    $ vault write venafi pki/venafi-policy/default \
        defaults_roles="venafi-role" enforcement_roles="venafi-role" \
        zone="DevOps\\Default" \
        url="https://tpp.example.com" trust_bundle_file="/path/to/bundle.pem" \
        access_token="tn1PwE1QTZorXmvnTowSyA==" refresh_token="MGxV7DzNnclQi9CkJMCXCg=="
    ```

    **Venafi Cloud**:

    ```text
    $ vault write venafi pki/venafi/policy-default \
        defaults_roles="venafi-role" enforcement_roles="venafi-role" \
        apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
        zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz"
    ```

5. Create a policy for Visibility. This will contain a zone where certificates issues by the Vault CA will be imported to. Visibility is enabled at the policy level using the `import_roles` parameter.

    **Trust Protection Platform**:

    ```text
    $ vault write pki/venafi-policy/visibility \
        import_roles="venafi-role" \
        zone="DevOps\\Vault Monitor" \
        url="https://tpp.example.com" trust_bundle_file="/path/to/bundle.pem" \
        access_token="tn1PwE1QTZorXmvnTowSyA==" refresh_token="MGxV7DzNnclQi9CkJMCXCg=="
    ```

    **Venafi Cloud**:

    ```text
    $ vault write pki/venafi/policy-visibility \
        import_roles="venafi-role" \
        zone="zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz" \
        apikey="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
    ```

## Usage

Venafi Policy limits the PKI role based on Venafi Platform policies or Venafi Cloud zones. Policy enforcement is configured using the special *venafi-policy* path which InfoSec teams can use to require compliance from a Vault CA. The Venafi monitoring plugin also places these requests in a queue that get imported back to Venafi Trust Protection Platform or Venafi Cloud.

1. Generate a certificate by writing to the Vault CA and the Venafi role.

   ```text
   $ vault write pki/issue/venafi-role common_name="test.allowed.org" alt_names="test-1.allowed.org,test-2.allowed.org"
   ```

   If the request is policy compliant, the request will return a certificate sucessfully. This certificate will also be placed in the visibility import queue to be uploaded to the Venafi Trust Protection Platform.

1. Or sign a CSR from a file by writing to the `/sign` endpoint with the name of the role: 

    ```text
    $ vault write pki/sign/venafi-policy csr=@test_example_com.csr
    ```

## Upgrading

To upgrade to a new version of this plugin, review the [release notes]() to understand the impact and then follow the [standard procedure](https://www.vaultproject.io/docs/upgrading/plugins). 
The following command will trigger a plug reload globally:

   ```text
   $ vault write sys/plugins/reload/backend plugin=vault-pki-monitor-venafi_strict scope=global

   Key          Value
   ---          -----
   reload_id    d8180af4-01e0-d4d8-10ce-0daf69fbb6ed
   ```

   :warning: **IMPORTANT:** Every member of a Vault cluster must be running with the same version of the plugin to avoid inconsistent, unexpected, and possibly erroneous results.

## License

Copyright &copy; Venafi, Inc. All rights reserved.

This solution is licensed under the Mozilla Public License, Version 2.0. See `LICENSE` for the full license text.

Please direct questions/comments to opensource@venafi.com.

