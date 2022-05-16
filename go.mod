module github.com/Venafi/vault-pki-monitor-venafi

go 1.13

require (
	github.com/Venafi/vcert/v4 v4.13.0
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/fatih/structs v1.1.0
	github.com/go-test/deep v1.0.7
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/vault v1.7.6
	github.com/hashicorp/vault/api v1.1.1
	github.com/hashicorp/vault/sdk v0.2.1-0.20211101201606-6453490da33b
	github.com/mitchellh/mapstructure v1.3.3
	github.com/ryanuber/go-glob v1.0.0
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210510120150-4163338589ed
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

replace gotest.tools/gotestsum => gotest.tools/gotestsum v0.5.4
