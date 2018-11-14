TEST?=$$(go list ./... |grep -v 'vendor')
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)

PLUGIN_NAME := vault-pki-monitor-venafi
PLUGIN_DIR := bin
PLUGIN_PATH := $(PLUGIN_DIR)/$(PLUGIN_NAME)

MOUNT := venafi-pki-import
SHA256 := $$(shasum -a 256 "$(PLUGIN_PATH)" | cut -d' ' -f1)

ROLE_OPTIONS := generate_lease=true store_by_cn="true" store_pkey="true" store_by_serial="true" ttl=1h max_ttl=1h
IMPORT_ROLE := import
IMPORT_DOMAIN := import.example.com
RANDOM_SITE_EXP := $$(head /dev/urandom | docker run --rm -i busybox tr -dc a-z0-9 | head -c 5 ; echo '')
TRUST_BUNDLE := "/tmp/chain.pem"

### Exporting variables for demo and tests
.EXPORT_ALL_VARIABLES:
VAULT_ADDR = http://127.0.0.1:8200
#Must be set,otherwise cloud certificates will timeout
VAULT_CLIENT_TIMEOUT = 180s

fmt:
	gofmt -w $(GOFMT_FILES)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

#Need to unset VAULT_TOKEN when running vault with dev parameter.
unset:
	unset VAULT_TOKEN

#Developement server tasks
dev_server: unset
	pkill vault || echo "Vault server is not running"
	vault server -log-level=debug -dev -config=vault-config.hcl

dev: build_go mount_dev

import: ca import_config_write import_config_read import_cert_write

ca:
	vault write $(MOUNT)/root/generate/internal \
        common_name=my-website.com \
        ttl=8760h

#Build and push
build_go:
	go build -o $(PLUGIN_PATH) || exit 1
	chmod +x $(PLUGIN_PATH)

mount_dev: unset
	vault write sys/plugins/catalog/$(PLUGIN_NAME) sha_256="$(SHA256)" command="$(PLUGIN_NAME)"
	vault secrets disable $(MOUNT) || echo "Secrets already disabled"
	vault secrets enable -path=$(MOUNT) -plugin-name=$(PLUGIN_NAME) plugin

import_config_write:
	vault write $(MOUNT)/roles/$(IMPORT_ROLE) \
		tpp_import="true"  \
		tpp_url=$(TPPURL) \
		tpp_user=$(TPPUSER) \
		tpp_password=$(TPPPASSWORD) \
		zone="$(TPPZONE)" \
		$(ROLE_OPTIONS) \
		allowed_domains=$(IMPORT_DOMAIN) \
		allow_subdomains=true \
		trust_bundle_file=$(TRUST_BUNDLE) \
		tpp_import_timeout=15

import_config_read:
	vault read $(MOUNT)/roles/$(IMPORT_ROLE)

import_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing import-$(RANDOM_SITE).$(IMPORT_DOMAIN)"
		vault write $(MOUNT)/issue/$(IMPORT_ROLE) common_name="import-$(RANDOM_SITE).$(IMPORT_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(IMPORT_DOMAIN),alt2-$(RANDOM_SITE).$(IMPORT_DOMAIN)"
