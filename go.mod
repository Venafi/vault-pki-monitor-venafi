module github.com/Venafi/vault-pki-monitor-venafi

go 1.13

require (
	github.com/DataDog/zstd v1.4.4 // indirect
	github.com/Venafi/vcert/v4 v4.13.0
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/fatih/structs v1.1.0
	github.com/go-test/deep v1.0.7
	github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/vault v1.6.6
	github.com/hashicorp/vault/api v1.0.5-0.20201001211907-38d91b749c77
	github.com/hashicorp/vault/sdk v0.1.14-0.20210824203509-535c9be10674
	github.com/mitchellh/mapstructure v1.3.3
	github.com/ryanuber/go-glob v1.0.0
	github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4 // indirect
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	gotest.tools/gotestsum v1.7.0 // indirect
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

replace gotest.tools/gotestsum => gotest.tools/gotestsum v0.5.4
