# HashiCorp Vault Secret Store certification testing

This project aims to test the [HashiCorp Vault Secret Store] component under various conditions.

This secret store [supports the following features][features]:
* Basic retrieve operations
* Multiple Keys under the same secret

# Test plan

## Basic Test for CRUD operations:
1. Able to create and test connection.
2. Able to do retrieve secrets.
3. Negative test to fetch record with key, that is not present.

## Test network instability
1. Vault component does not expose a time out configuration option. For this test, let's assume a 1 minute timeout.
2. Retrieve a key to show the connection is fine.
3. Interrupt the network on Vault's port (8200) for longer than the established timeout value.
4. Wait a few seconds (less than the timeout value).
5. Try to read the key from step 2 and assert it is still there.


## Test support for multiple keys under the same secret
1. Test retrieval of secrets with multiple keys under it.

## Tests for metadata fields

### Tests for `vaultKVPrefix`, `vaultKVUsePrefix` and `vaultValueTypeText`

1. Verify `vaultKVPrefix` is used
    * set field to to non default value
    * run dapr application with component
    * component should successfully initialize
    * component should advertise `multipleKeyValuesPerSecret` feature
    * retrieval of key under registered under new prefix should succeed
    * keys under default and empty prefixes should be missing
1. Verify `vaultKVUsePrefix` is used
    * set field to `false` (non default value)
    * run dapr application with component
    * component should successfully initialize
    * component should advertise `multipleKeyValuesPerSecret` feature
    * retrieval of key registered without (empty) prefix should succeed
    * keys under default and non-default prefix from step above should be missing
1. Verify `vaultValueTypeText` is used
    * set field to to non default value `text`
    * run dapr application with component
    * component should successfully initialize
    * component should **not** advertise `multipleKeyValuesPerSecret` feature
    * retrieval of key under registered under new prefix should succeed
    * keys under default and empty prefixes should be missing


### Tests for `vaultToken` and `vaultTokenMountPath`

1. Verify `vaultToken` is used (happy case)
    * The baseline fo this test is all the previous test are using a known-to-work value that matches what our docker-compose environment sets up.
1. Verify failure when we use a `vaultToken` value that does not match what our environment sets up
1. Verify `vaultTokenMountPath` is used (happy case)
1. Verify failure when `vaultTokenMountPath` points to a broken path
1. Verify failure when both `vaultToken` and `vaultTokenMountPath` are missing
1. Verify failure when both `vaultToken` and `vaultTokenMountPath` are present

## Pending 

### Tests for enginePath

1. `enginePath`


### Tests for vaultAddr

1. Verify `vaultAddr` is used (happy case)
    * The baseline fo this test is all the previous test are using a known-to-work value that matches what our docker-compose environment sets up.
1. Verify `vaultAddr` is used when it points to a non-std port 
1. Verify failure when `vaultAddr` points to an address not served by a Vault
1. Verify failure when `vaultAddr` is missing <<<< THIS IS A QUICK TEST, STOPPED HERE>>>>

### Tests for CA and other certificate-related parameters

1. caCert
1. caPath
1. caPem
1. skipVerify



## Out of scope

1. Tests verifying writing and updating a secret since secret stores do not expose this functionality. 


## Running the tests

Under the current directory run:

```
GOLANG_PROTOBUF_REGISTRATION_CONFLICT=warn go test -v vault_test.go
```

# References:

* [HashiCorp Vault Secret Store Component reference page][HashiCorp Vault Secret Store]
* [List of secret store components and their features][features]
* [PR with Conformance tests for Hashicorp Vault][conformance]
* [HashiCorp Vault API reference](https://www.vaultproject.io/api-docs)

[HashiCorp Vault Secret Store]: https://docs.dapr.io/reference/components-reference/supported-secret-stores/hashicorp-vault/
[features]: https://docs.dapr.io/reference/components-reference/supported-secret-stores/
[conformance]: https://github.com/dapr/components-contrib/pull/2031