# Secrets Engine Plugin Versions

Unfortunately, the HashiCorp Vault plugin architecture does not provide developers with a way to
communicate the actual version of their plugins to Vault administrators.  Instead administrators
must rely on the SHA256 hash of the plugin binary to differentiate one version of a plugin from
another.  

Listed below are the SHA256 hashes of plugins from recent official releases, provided to help
simplify the task of identifying which version of the *Venafi PKI Monitoring Secrets Engine for
HashiCorp Vault* you are currently using.

### v0.9.0
```
276a7122d16f6c2b4a27c4a9592e4d52a584cf6c92f899870b2d4053736cdeb1  darwin_optional     venafi-pki-monitor_optional
f59c3e7072c08c9cf2a5e19fb1dd93ffa0e9946ce950fb354ca2fb58fe12e235  darwin_strict       venafi-pki-monitor
41b9642cb96090672c48f7964857286ea3edb830b6c2300bd26505d46971f885  linux86_optional    venafi-pki-monitor_optional
9a53551910a29a0d457f1475730d271f4c7debe3e724c57886def86d3a3614b3  linux86_strict      venafi-pki-monitor
5862ad98bc639a81faf55234f30b6aff6852c7a2fb289009bca7985db2122392  linux_optional      venafi-pki-monitor_optional
977980444b0509e425877f484f234c71de4379781c7cdfc38bc487702a5e714d  linux_strict        venafi-pki-monitor
6d4bb8e8bb93e156e462986f177f81c9f4a80579b0051605d74228f7bf4ba567  windows86_optional  venafi-pki-monitor_optional.exe
6f4d63bc59eb4f03db3d049043cb8ac66fda33c6577b420c0993ab426082493d  windows86_strict    venafi-pki-monitor.exe
c0a869468a6d230979ce5023284c1bd423f1ba54b046f481191ed5db835b82ed  windows_optional    venafi-pki-monitor_optional.exe
69ca0415ea9e5b09060ce72a9f1e71e7c89213a60f3d3f1ec9625a9ed88b92d6  windows_strict      venafi-pki-monitor.exe
```

### v0.8.3
```
43b5e3d3fd7eb3cc5f93e518a7bbe22eacda93b62eda1e45b7feb1d0c0c11188  darwin_optional     venafi-pki-monitor_optional
8af40858fc39c1a21eeb5a26097a089e5a99d54052b7062a402bf3301600b2d7  darwin_strict       venafi-pki-monitor
10aec6cb55947abd24c352eaa708c085daea38d8c38987aedac8cc892c9600ff  linux86_optional    venafi-pki-monitor_optional
10de301eb1e082c6ede21bed052177c98421f99bf9e1a196397cd3ac35aba636  linux86_strict      venafi-pki-monitor
32af916f48676c4083549bd45ad59e0d0bac9fbf863caef2b6ad2bab3b92596c  linux_optional      venafi-pki-monitor_optional
cb2186123fac03d6c9c8524505f46e383188a2605bb97e916d3c25aad42bfe93  linux_strict        venafi-pki-monitor
a1b293cf818ab1281447db0ae7e2cd77819ed908f03af5d393d5ae079aa5e706  windows86_optional  venafi-pki-monitor_optional.exe
c5a6432a5f222bc057a3023a93cd6ea99d05669db3f8dd9d41eabb9fd5303a1f  windows86_strict    venafi-pki-monitor.exe
f2fb285904cd4f4c2813b2d5387d7525488abb8880e54f54e32d884136f922ff  windows_optional    venafi-pki-monitor_optional.exe
a0e72036eb55193c2ee3c417c44fb5a4081556f3d67b3332ba6a772087de0569  windows_strict      venafi-pki-monitor.exe
```

### v0.8.2
```
7ecac55684d69159829819c7bf764f837e65b34431fd46629fcb9de2ac989b51  darwin_optional     venafi-pki-monitor_optional
0e68c90ce69f4d75d98994477eacd020945c5b832700e36bf954cb97ab0f9b31  darwin_strict       venafi-pki-monitor
1ea31ffa88f88d5488a5ecba0b16dadec046b9872d69881edb483baea73db3c1  linux86_optional    venafi-pki-monitor_optional
3cb74ef23d200108bdb09208ec8719128a83951165badbdc55a05f72c856e3ec  linux86_strict      venafi-pki-monitor
021842e629af5e41d6e1fee0d79b712efacb1e042525d4a4ebe092a40e5775ec  linux_optional      venafi-pki-monitor_optional
9fc2200565d24ff77e4a1679259461a2ad1a6ac8221254ab661b15cead026a7e  linux_strict        venafi-pki-monitor
be4fbe88926ec0e6b97ed83071e97b0cadbbb4f3605d2e157f5738c3bbad4af7  windows86_optional  venafi-pki-monitor_optional.exe
23a26e27090e53054f6bafd79693343a1e5f63b7ae88e0f748e377ecf88c3018  windows86_strict    venafi-pki-monitor.exe
cec348f58da70295b8df39b84769527ad02770de81ed1016da5dfe7ad21425c2  windows_optional    venafi-pki-monitor_optional.exe
8f9c4d2a0b10bb477f9ec3ca052f7347d1caffb818024fefda06ee7042c860a9  windows_strict      venafi-pki-monitor.exe
```

### v0.8.1
```
5fc7efdcb1e4a6fbbfbb48eb1c4188d91b38c84f5887c23e475c2d5329132275  darwin86_optional   vault-pki-monitor-venafi_optional
5fc7efdcb1e4a6fbbfbb48eb1c4188d91b38c84f5887c23e475c2d5329132275  darwin86_strict     vault-pki-monitor-venafi_strict
a2a81b522a1b3529a628477c02367e0ccff9746a2f151736d59d64896b85b9cd  darwin_optional     vault-pki-monitor-venafi_optional
a2a81b522a1b3529a628477c02367e0ccff9746a2f151736d59d64896b85b9cd  darwin_strict       vault-pki-monitor-venafi_strict
3630018e5210090c28931dc8344b5c5fc42b50fca8c2c57966991923f6320e01  linux86_optional    vault-pki-monitor-venafi_optional
3630018e5210090c28931dc8344b5c5fc42b50fca8c2c57966991923f6320e01  linux86_strict      vault-pki-monitor-venafi_strict
a11e4b4f29c7fe646511c2b49138fb83cbe5899efe2302e0db30836f94c7f816  linux_optional      vault-pki-monitor-venafi_optional
a11e4b4f29c7fe646511c2b49138fb83cbe5899efe2302e0db30836f94c7f816  linux_strict        vault-pki-monitor-venafi_strict
d976efc00b986af5970c0ee8da794c8db7071c6d5fd6675144235bff090a2d2c  windows86_optional  vault-pki-monitor-venafi_optional.exe
d976efc00b986af5970c0ee8da794c8db7071c6d5fd6675144235bff090a2d2c  windows86_strict    vault-pki-monitor-venafi_strict.exe
f364007fc58da646a70bf59211b2c4ba315f47f28276616048fece37e7871543  windows_optional    vault-pki-monitor-venafi_optional.exe
f364007fc58da646a70bf59211b2c4ba315f47f28276616048fece37e7871543  windows_strict      vault-pki-monitor-venafi_strict.exe
```

### v0.8.0
```
13729a38ba5038b6236bcc6b6a6cc7a5686412bcbbea1ff1768892f03c2047c2  darwin86_optional   vault-pki-monitor-venafi_optional
13729a38ba5038b6236bcc6b6a6cc7a5686412bcbbea1ff1768892f03c2047c2  darwin86_strict     vault-pki-monitor-venafi_strict
090580a6b3c8156b3a3a63c8d78614c22e0bf97902f7cb06389eafb2d2103a97  darwin_optional     vault-pki-monitor-venafi_optional
090580a6b3c8156b3a3a63c8d78614c22e0bf97902f7cb06389eafb2d2103a97  darwin_strict       vault-pki-monitor-venafi_strict
91ad36eccc10a77d4acc23ede392532d9adf88acee3b0cf05d80aa2e17f5ee5d  linux86_optional    vault-pki-monitor-venafi_optional
91ad36eccc10a77d4acc23ede392532d9adf88acee3b0cf05d80aa2e17f5ee5d  linux86_strict      vault-pki-monitor-venafi_strict
592a340ba56ce3b804bbc2398ba158aaf96465a8619405a3f193048a81ddddd0  linux_optional      vault-pki-monitor-venafi_optional
592a340ba56ce3b804bbc2398ba158aaf96465a8619405a3f193048a81ddddd0  linux_strict        vault-pki-monitor-venafi_strict
b5b87db682cbfdf3366cc472ec23ac787b1052035a97d4ef5d0067d19afd4032  windows86_optional  vault-pki-monitor-venafi_optional.exe
b5b87db682cbfdf3366cc472ec23ac787b1052035a97d4ef5d0067d19afd4032  windows86_strict    vault-pki-monitor-venafi_strict.exe
347eda31eebf504c7370db5aef94e3c992550d817e64e5509bf90be2e1e78605  windows_optional    vault-pki-monitor-venafi_optional.exe
347eda31eebf504c7370db5aef94e3c992550d817e64e5509bf90be2e1e78605  windows_strict      vault-pki-monitor-venafi_strict.exe
```