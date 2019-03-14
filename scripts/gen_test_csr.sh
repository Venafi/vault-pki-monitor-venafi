#!/usr/bin/env bash
openssl req -new -newkey rsa:4096 -nodes -out allowed.csr -keyout allowed.key -config allowed_csr.conf
openssl req -new -newkey rsa:4096 -nodes -out allowed_empty.csr -keyout allowed_empty.key -config allowed_empty_csr.conf
openssl req -new -newkey rsa:4096 -nodes -out wrong.csr -keyout wrong.key -config wrong_csr.conf
