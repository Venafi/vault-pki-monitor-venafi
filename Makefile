# Metadata about this makefile and position
MKFILE_PATH := $(lastword $(MAKEFILE_LIST))
CURRENT_DIR := $(patsubst %/,%,$(dir $(realpath $(MKFILE_PATH))))


# List of tests to run
TEST ?= $$(go list ./... | grep -v /vendor/ | grep -v /e2e)
TEST_TIMEOUT?=20m
GOFMT_FILES?=$$(find . -name '*.go' |grep -v vendor)

#Plugin information
PLUGIN_NAME := vault-pki-monitor-venafi
PLUGIN_DIR := pkg/bin
PLUGIN_PATH := $(PLUGIN_DIR)/$(PLUGIN_NAME)
DIST_DIR := pkg/dist
ifdef BUILD_NUMBER
VERSION=`git describe --abbrev=0 --tags`+$(BUILD_NUMBER)
else
VERSION=`git describe --abbrev=0 --tags`
endif

#define version if release is set
ifdef RELEASE_VERSION
ifdef BUILD_NUMBER
VERSION=$(RELEASE_VERSION)+$(BUILD_NUMBER)
else
VERSION=$(RELEASE_VERSION)
endif
endif

#test demo vars
IMPORT_DOMAIN := import.example.com
IMPORT_ROLE := import
MOUNT := pki
RANDOM_SITE_EXP := $$(head /dev/urandom | docker run --rm -i busybox tr -dc a-z0-9 | head -c 5 ; echo '')
ROLE_OPTIONS := generate_lease=true ttl=1h max_ttl=1h
SHA256 := $$(shasum -a 256 "$(PLUGIN_PATH)" | cut -d' ' -f1)
TRUST_BUNDLE := /opt/venafi/bundle.pem

#Docker vars
VAULT_CONT := $$(docker-compose ps |grep Up|grep vault_1|awk '{print $$1}')
DOCKER_CMD := docker exec -it $(VAULT_CONT)
VAULT_CMD := $(DOCKER_CMD) vault
SHA256_DOCKER_CMD := sha256sum "/vault_plugin/$(PLUGIN_NAME)" | cut -d' ' -f1

### Exporting variables for demo and tests
.EXPORT_ALL_VARIABLES:
VAULT_ADDR = http://127.0.0.1:8200
#Must be set,otherwise cloud certificates will timeout
VAULT_CLIENT_TIMEOUT = 180s

test: linter
	VAULT_ACC=1 \
	go get gotest.tools/gotestsum
	gotestsum --junitfile  junit.xml  -- -timeout $(TEST_TIMEOUT) ./...

policy_test:
	go test github.com/Venafi/vault-pki-monitor-venafi/plugin/pki -run ^TestBackend_VenafiPolicy*$

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

dev: dev_build mount_dev

import: ca import_config_write import_config_read import_cert_write

ca:
	vault write $(MOUNT)/root/generate/internal \
        common_name=my-website.com \
        ttl=8760h

#Build
clean:
	rm -rf $(PLUGIN_DIR)
	rm -rf $(DIST_DIR)
	rm -rf artifcats

build: build_strict build_optional

build_strict:
	scripts/build.sh $(PLUGIN_NAME) $(PLUGIN_DIR) $(DIST_DIR) strict $(VERSION)

build_optional:
	scripts/build.sh $(PLUGIN_NAME) $(PLUGIN_DIR) $(DIST_DIR) optional $(VERSION)


dev_build:
	sed -i 's/const venafiPolicyDenyAll =.*/const venafiPolicyDenyAll = true/' plugin/pki/vcert.go
	env CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags '$(LDFLAGS_STRICT)' -a -o $(PLUGIN_DIR)/$(PLUGIN_NAME) || exit 1


mount_dev: unset
	vault write sys/plugins/catalog/$(PLUGIN_NAME) sha_256="$(SHA256)" command="$(PLUGIN_NAME)"
	vault secrets disable $(MOUNT) || echo "Secrets already disabled"
	vault secrets enable -path=$(MOUNT) -plugin-name=$(PLUGIN_NAME) plugin

import_config_write:
	vault write $(MOUNT)/roles/$(IMPORT_ROLE) \
		venafi_import="true"  \
		tpp_url=$(TPP_URL) \
		tpp_user=$(TPP_USER) \
		tpp_password=$(TPP_PASSWORD) \
		zone="$(TPP_ZONE)" \
		$(ROLE_OPTIONS) \
		allowed_domains=$(IMPORT_DOMAIN) \
		allow_subdomains=true \
		trust_bundle_file=$(TRUST_BUNDLE) \
		import_timeout=15 \
		import_workers=5

import_config_read:
	vault read $(MOUNT)/roles/$(IMPORT_ROLE)

import_cert_write:
	$(eval RANDOM_SITE := $(shell echo $(RANDOM_SITE_EXP)))
	@echo "Issuing import-$(RANDOM_SITE).$(IMPORT_DOMAIN)"
		vault write $(MOUNT)/issue/$(IMPORT_ROLE) common_name="import-$(RANDOM_SITE).$(IMPORT_DOMAIN)" alt_names="alt-$(RANDOM_SITE).$(IMPORT_DOMAIN),alt2-$(RANDOM_SITE).$(IMPORT_DOMAIN)"


collect_artifacts:
	rm -rf artifcats
	mkdir -p artifcats
	cp -rv $(DIST_DIR)/*.zip artifcats
	cd artifcats; echo '```' > ../release.txt
	cd artifcats; sha256sum * >> ../release.txt
	cd artifcats; echo '```' >> ../release.txt

release:
	go get -u github.com/tcnksm/ghr
	ghr -prerelease -n $$RELEASE_VERSION -body="$$(cat ./release.txt)" $$RELEASE_VERSION artifcats/

#Docker server with consul
docker_server_prepare:
	@echo "Using vault client version $(VAULT_VERSION)"
ifeq ($(VAULT_VERSION),v0.10.3)
	@echo "Vault version v0.10.3 have bug which prevents plugin to work properly. Please update your vault client"
	@exit 1
endif

docker_server_up:
	docker-compose up -d --build
	@echo "Run: docker-compose logs"
	@echo "to see the logs"
	@echo "Run: docker exec -it cault_vault_1 sh"
	@echo "to login into vault container"
	@echo "Waiting until server start"
	sleep 10


docker_server_init:
	$(VAULT_CMD) operator init -key-shares=1 -key-threshold=1
	@echo "To unseal the vault run:"
	@echo "$(VAULT_CMD) operator unseal UNSEAL_KEY"

docker_server_unseal:
	@echo Enter unseal key:
	$(VAULT_CMD) operator unseal

docker_server_login:
	@echo Enter root token:
	$(VAULT_CMD) login

docker_server_down:
	docker-compose down --remove-orphans

docker_server_logs:
	docker-compose logs -f

docker_server_sh:
	$(DOCKER_CMD) sh

docker_server: docker_server_prepare docker_server_down docker_server_up docker_server_init docker_server_unseal docker_server_login mount_docker
	@echo "Vault started. To run make command export VAULT_TOKEN variable and run make with -e flag, for example:"
	@echo "export VAULT_TOKEN=enter-root-token-here"
	@echo "make cloud -e"

mount_docker:
	$(eval SHA256 := $(shell echo $$($(DOCKER_CMD) $(SHA256_DOCKER_CMD))))
	$(VAULT_CMD) write sys/plugins/catalog/$(PLUGIN_NAME) sha_256="$$SHA256" command="$(PLUGIN_NAME)"
	$(VAULT_CMD) secrets disable $(MOUNT) || echo "Secrets already disabled"
	$(VAULT_CMD) secrets enable -path=$(MOUNT) -plugin-name=$(PLUGIN_NAME) plugin

linter:
	golangci-lint run
