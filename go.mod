module github.com/Venafi/vault-pki-monitor-venafi

go 1.13

require (
	github.com/Venafi/vcert/v4 v4.11.1
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/fatih/structs v1.1.0
	github.com/go-test/deep v1.0.7
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/vault v1.5.5
	github.com/hashicorp/vault/api v1.0.5-0.20200630205458-1a16f3c699c6
	github.com/hashicorp/vault/sdk v0.1.14-0.20201020233143-625c50e68971
	github.com/mitchellh/mapstructure v1.3.2
	github.com/ryanuber/go-glob v1.0.0
	golang.org/x/crypto v0.0.0-20200604202706-70a84ac30bf9
	golang.org/x/net v0.0.0-20200602114024-627f9648deb9
	gotest.tools/gotestsum v0.6.0 // indirect
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

replace gotest.tools/gotestsum => gotest.tools/gotestsum v0.5.4
