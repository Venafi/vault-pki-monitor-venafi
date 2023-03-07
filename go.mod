module github.com/Venafi/vault-pki-monitor-venafi

go 1.13

require (
	github.com/Venafi/vcert/v4 v4.13.0
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/fatih/structs v1.1.0
	github.com/go-test/deep v1.0.8
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/vault v1.9.9
	github.com/hashicorp/vault/api v1.3.1
	github.com/hashicorp/vault/sdk v0.3.1-0.20220721224749-00773967ab3a
	github.com/mitchellh/mapstructure v1.4.3
	github.com/ryanuber/go-glob v1.0.0
	github.com/tencentcloud/tencentcloud-sdk-go v3.0.171+incompatible // indirect
	golang.org/x/crypto v0.0.0-20220208050332-20e1d8d225ab
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd
)

replace github.com/hashicorp/vault/api => github.com/hashicorp/vault/api v0.0.0-20200718022110-340cc2fa263f

replace gotest.tools/gotestsum => gotest.tools/gotestsum v0.5.4
