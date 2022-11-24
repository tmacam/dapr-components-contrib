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


### Tests for vaultAddr

1. Verify `vaultAddr` is used (happy case)
    * The baseline fo this test is all the previous test are using this flag with a known-to-work value that matches what our docker-compose environment sets up and is **not the default**.
1. Verify initialization and operation success when `vaultAddr` is missing  `skipVerify` is `true`
    * Start a vault instance using a self-signed HTTPS certificate.
    * Component configuration lacks `vaultAddr` and defaults to address `https://127.0.0.1:8200`
    * Due to `skipVerify` the component accepts the self-signed certificate
1. Verify initialization success but operation failure when `vaultAddr` is missing  `skipVerify` is `false`
    * Start a vault instance using a self-signed HTTPS certificate.
    * Component configuration lacks `vaultAddr` and defaults to address `https://127.0.0.1:8200`
    * Since `skipVerify` is disable the component requires a valid TLS certificate and refuses to connect to our vault instance, failing requests.
1. Verify `vaultAddr` is used when it points to a non-std port
    * Start a vault instance in dev-mode (HTTP) but listening on a non-std port
    * Modify component configuration to use this non-std port
    * Ensure component initialization success and successful retrieval of secrets
1. Verify successful initialization but secret retrieval failure  when `vaultAddr` points to an address not served by a Vault
    * Start a vault instance in dev-mode (HTTP) listening on std port
    * Modify component configuration to use a distinct (non-std) port
    * Ensure component initialization success but secret retrieval failure


### Tests for enginePath

1. Verify that setting `enginePath` to an explicit default value works
1. Verify that setting `enginePath` to a custom value (`TestEnginePathCustomSecretsPath`) works
    * Start a vault instance in dev-mode
    * In the companion shell script that seeds the vault instance with secrets,
        1. Create a new **path** named `customSecretsPath` that uses the KV engine version 2 (`-version=2 kv` or `kv-v2`)
            * We cannot use version 1 as the vault component lacks support for non-versioned engines.
        2. Seeds this path with a secret specific for this test (to avoid the risk of false-positive tests)
    * Verify that the custom path has secrets under it using BulkList (this is a sanity check)
    * Verify that the custom path-specific secret is found


## Pending 




### Tests for CA and other certificate-related parameters

1. caCert
1. caPath
1. caPem

1. skipVerify
* Tested with `vaultAddr`


VERSIONS!!!! Are we able to retrieve a given version of a secret?

## Out of scope


1. Verifying how vault handles request for past versions of a secret
    * Vault only handles engines with version support
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