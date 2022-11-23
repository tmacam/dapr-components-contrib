/*
Copyright 2021 The Dapr Authors
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vault_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dapr/components-contrib/secretstores"
	"github.com/dapr/components-contrib/secretstores/hashicorp/vault"
	"github.com/dapr/components-contrib/tests/certification/embedded"
	"github.com/dapr/components-contrib/tests/certification/flow"
	"github.com/dapr/components-contrib/tests/certification/flow/dockercompose"
	"github.com/dapr/components-contrib/tests/certification/flow/network"
	"github.com/dapr/components-contrib/tests/certification/flow/sidecar"
	secretstores_loader "github.com/dapr/dapr/pkg/components/secretstores"
	"github.com/dapr/dapr/pkg/runtime"
	dapr_testing "github.com/dapr/dapr/pkg/testing"
	"github.com/dapr/go-sdk/client"
	"github.com/dapr/kit/logger"
	"github.com/stretchr/testify/assert"

	"github.com/golang/protobuf/ptypes/empty"
)

const (
	sidecarName              = "hashicorp-vault-sidecar"
	dockerComposeClusterYAML = "../../../../../.github/infrastructure/docker-compose-hashicorp-vault.yml"
	dockerComposeProjectName = "hashicorp-vault"
	// secretStoreName          = "my-hashicorp-vault" // as set in the component YAML

	networkInstabilityTime   = 1 * time.Minute
	waitAfterInstabilityTime = networkInstabilityTime / 4
	servicePortToInterrupt   = "8200"
)

func TestBasicSecretRetrieval(t *testing.T) {
	const (
		secretStoreComponentPath = "./components/default"
		secretStoreName          = "my-hashicorp-vault" // as set in the component YAML
	)

	ports, err := dapr_testing.GetFreePorts(2)
	assert.NoError(t, err)

	currentGrpcPort := ports[0]
	currentHttpPort := ports[1]

	testGetKnownSecret := func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		emptyOpt := map[string]string{}

		// This test reuses the HashiCorp Vault's conformance test resources created using
		// .github/infrastructure/docker-compose-hashicorp-vault.yml,
		// so it reuses the tests/conformance/secretstores/secretstores.go test secrets.
		res, err := client.GetSecret(ctx, secretStoreName, "secondsecret", emptyOpt)
		assert.NoError(t, err)
		assert.Equal(t, "efgh", res["secondsecret"])
		return nil
	}

	testGetMissingSecret := func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		emptyOpt := map[string]string{}

		_, getErr := client.GetSecret(ctx, secretStoreName, "this_secret_is_not_there", emptyOpt)
		assert.Error(t, getErr)

		return nil
	}

	flow.New(t, "Test component is up and we can retrieve some secrets").
		Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
		Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
		Step(sidecar.Run(sidecarName,
			embedded.WithoutApp(),
			embedded.WithComponentsPath(secretStoreComponentPath),
			embedded.WithDaprGRPCPort(currentGrpcPort),
			embedded.WithDaprHTTPPort(currentHttpPort),
			componentRuntimeOptions(),
		)).
		Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
		Step("Verify component is registered", testComponentFound(t, secretStoreName, currentGrpcPort)).
		Step("Run basic secret retrieval test", testGetKnownSecret).
		Step("Test retrieval of secret that does not exist", testGetMissingSecret).
		Step("Interrupt network for 1 minute",
			network.InterruptNetwork(networkInstabilityTime, nil, nil, servicePortToInterrupt)).
		Step("Wait for component to recover", flow.Sleep(waitAfterInstabilityTime)).
		Step("Run basic test again to verify reconnection occurred", testGetKnownSecret).
		Step("Stop HashiCorp Vault server", dockercompose.Stop(dockerComposeProjectName, dockerComposeClusterYAML)).
		Run()
}

func TestMultipleKVRetrieval(t *testing.T) {
	const (
		secretStoreComponentPath = "./components/default"
		secretStoreName          = "my-hashicorp-vault" // as set in the component YAML
	)

	currentGrpcPort, currentHttpPort := GetCurrentGRPCAndHTTPPort(t)

	flow.New(t, "Test retrieving multiple key values from a secret").
		Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
		Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
		Step(sidecar.Run(sidecarName,
			embedded.WithoutApp(),
			embedded.WithComponentsPath(secretStoreComponentPath),
			embedded.WithDaprGRPCPort(currentGrpcPort),
			embedded.WithDaprHTTPPort(currentHttpPort),
			componentRuntimeOptions(),
		)).
		Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
		Step("Verify component is registered", testComponentFound(t, secretStoreName, currentGrpcPort)).
		Step("Verify component has support for multiple key-values under the same secret",
			testComponentHasFeature(t, currentGrpcPort, secretStoreName, secretstores.FeatureMultipleKeyValuesPerSecret)).
		Step("Test retrieval of a secret with multiple key-values",
			testKeyValuesInSecret(t, currentGrpcPort, secretStoreName, "multiplekeyvaluessecret", map[string]string{
				"first":  "1",
				"second": "2",
				"third":  "3",
			})).
		Step("Test secret registered under a non-default vaultKVPrefix cannot be found",
			testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretUnderAlternativePrefix")).
		Step("Test secret registered with no prefix cannot be found", testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretWithNoPrefix")).
		Step("Stop HashiCorp Vault server", dockercompose.Stop(dockerComposeProjectName, dockerComposeClusterYAML)).
		Run()
}

func TestVaultKVPrefix(t *testing.T) {
	const (
		secretStoreComponentPath = "./components/vaultKVPrefix"
		secretStoreName          = "my-hashicorp-vault" // as set in the component YAML
	)

	currentGrpcPort, currentHttpPort := GetCurrentGRPCAndHTTPPort(t)

	flow.New(t, "Test setting a non-default vaultKVPrefix value").
		Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
		Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
		Step(sidecar.Run(sidecarName,
			embedded.WithoutApp(),
			embedded.WithComponentsPath(secretStoreComponentPath),
			embedded.WithDaprGRPCPort(currentGrpcPort),
			embedded.WithDaprHTTPPort(currentHttpPort),
			componentRuntimeOptions(),
		)).
		Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
		Step("Verify component is registered", testComponentFound(t, secretStoreName, currentGrpcPort)).
		Step("Verify component has support for multiple key-values under the same secret",
			testComponentHasFeature(t, currentGrpcPort, secretStoreName, secretstores.FeatureMultipleKeyValuesPerSecret)).
		Step("Test retrieval of a secret under a non-default vaultKVPrefix",
			testKeyValuesInSecret(t, currentGrpcPort, secretStoreName, "secretUnderAlternativePrefix", map[string]string{
				"altPrefixKey": "altPrefixValue",
			})).
		Step("Test secret registered with no prefix cannot be found", testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretWithNoPrefix")).
		Step("Stop HashiCorp Vault server", dockercompose.Stop(dockerComposeProjectName, dockerComposeClusterYAML)).
		Run()
}

func TestVaultKVUsePrefixFalse(t *testing.T) {
	const (
		secretStoreComponentPath = "./components/vaultKVUsePrefixFalse"
		secretStoreName          = "my-hashicorp-vault" // as set in the component YAML
	)

	currentGrpcPort, currentHttpPort := GetCurrentGRPCAndHTTPPort(t)

	flow.New(t, "Test using an empty vaultKVPrefix value").
		Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
		Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
		Step(sidecar.Run(sidecarName,
			embedded.WithoutApp(),
			embedded.WithComponentsPath(secretStoreComponentPath),
			embedded.WithDaprGRPCPort(currentGrpcPort),
			embedded.WithDaprHTTPPort(currentHttpPort),
			componentRuntimeOptions(),
		)).
		Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
		Step("Verify component is registered", testComponentFound(t, secretStoreName, currentGrpcPort)).
		Step("Verify component has support for multiple key-values under the same secret",
			testComponentHasFeature(t, currentGrpcPort, secretStoreName, secretstores.FeatureMultipleKeyValuesPerSecret)).
		Step("Test retrieval of a secret registered with no prefix and assuming vaultKVUsePrefix=false",
			testKeyValuesInSecret(t, currentGrpcPort, secretStoreName, "secretWithNoPrefix", map[string]string{
				"noPrefixKey": "noProblem",
			})).
		Step("Test secret registered under the default vaultKVPrefix cannot be found",
			testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "multiplekeyvaluessecret")).
		Step("Test secret registered under a non-default vaultKVPrefix cannot be found",
			testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretUnderAlternativePrefix")).
		Step("Stop HashiCorp Vault server", dockercompose.Stop(dockerComposeProjectName, dockerComposeClusterYAML)).
		Run()
}

func TestVaultValueTypeText(t *testing.T) {
	const (
		secretStoreComponentPath = "./components/vaultValueTypeText"
		secretStoreName          = "my-hashicorp-vault" // as set in the component YAML
	)

	currentGrpcPort, currentHttpPort := GetCurrentGRPCAndHTTPPort(t)

	flow.New(t, "Test setting vaultValueType=text should cause it to behave with single-value semantics").
		Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
		Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
		Step(sidecar.Run(sidecarName,
			embedded.WithoutApp(),
			embedded.WithComponentsPath(secretStoreComponentPath),
			embedded.WithDaprGRPCPort(currentGrpcPort),
			embedded.WithDaprHTTPPort(currentHttpPort),
			componentRuntimeOptions(),
		)).
		Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
		Step("Verify component is registered", testComponentFound(t, secretStoreName, currentGrpcPort)).
		Step("Verify component DOES NOT support  multiple key-values under the same secret",
			testComponentDoesNotHaveFeature(t, currentGrpcPort, secretStoreName, secretstores.FeatureMultipleKeyValuesPerSecret)).
		Step("Test secret store presents name/value semantics for secrets",
			// result has a single key with tha same name as the secret and a JSON-like content
			testKeyValuesInSecret(t, currentGrpcPort, secretStoreName, "secondsecret", map[string]string{
				"secondsecret": "{\"secondsecret\":\"efgh\"}",
			})).
		Step("Test secret registered under a non-default vaultKVPrefix cannot be found",
			testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretUnderAlternativePrefix")).
		Step("Test secret registered with no prefix cannot be found", testSecretIsNotFound(t, currentGrpcPort, secretStoreName, "secretWithNoPrefix")).
		Step("Stop HashiCorp Vault server", dockercompose.Stop(dockerComposeProjectName, dockerComposeClusterYAML)).
		Run()
}

type initErrorChecker func(ctx flow.Context, errorLine string) error

func captureLogsAndCheckInitErrors(checker initErrorChecker) flow.Runnable {
	// Setup log capture
	logCaptor := &bytes.Buffer{}
	runtimeLogger := logger.NewLogger("dapr.runtime")
	runtimeLogger.SetOutput(io.MultiWriter(os.Stdout, logCaptor))

	// Stop log capture, reset buffer just for good mesure
	cleanup := func() {
		logCaptor.Reset()
		runtimeLogger.SetOutput(os.Stdout)
	}

	grepInitErrorFromLogs := func() (string, error) {
		errorMarker := []byte("INIT_COMPONENT_FAILURE")
		scanner := bufio.NewScanner(logCaptor)
		for scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", err
			}
			if bytes.Contains(scanner.Bytes(), errorMarker) {
				return scanner.Text(), nil
			}
		}
		return "", scanner.Err()
	}

	// Wraps the our initErrorChecker with cleanup and error-grepping logic so we only care about the
	// log error
	return func(ctx flow.Context) error {
		defer cleanup()

		errorLine, err := grepInitErrorFromLogs()
		if err != nil {
			return err
		}
		ctx.Logf("👀 errorLine: %s", errorLine)

		return checker(ctx, errorLine)
	}
}

func assertNoInitializationErrorsForComponent(componentName string) flow.Runnable {
	checker := func(ctx flow.Context, errorLine string) error {
		componentFailedToInitialize := strings.Contains(errorLine, componentName)
		assert.False(ctx.T, componentFailedToInitialize,
			"Found component name mentioned in an component initialization error message: %s", errorLine)

		return nil
	}

	return captureLogsAndCheckInitErrors(checker)
}

func assertInitializationFailedWithErrorsForComponent(componentName string, additionalSubStringsToMatch ...string) flow.Runnable {
	checker := func(ctx flow.Context, errorLine string) error {
		assert.NotEmpty(ctx.T, errorLine, "Expected a component initialization error message but none found")
		assert.Contains(ctx.T, errorLine, componentName,
			"Expected to find component '%s' mentioned in error message but found none: %s", componentName, errorLine)

		for _, subString := range additionalSubStringsToMatch {
			assert.Contains(ctx.T, errorLine, subString,
				"Expected to find '%s' mentioned in error message but found none: %s", componentName, errorLine)
		}

		return nil
	}

	return captureLogsAndCheckInitErrors(checker)
}

func TestTokenAndTokenMountPath(t *testing.T) {
	const (
		secretStoreComponentPathBase = "./components/vaultTokenAndTokenMountPath/"
	)

	currentGrpcPort, currentHttpPort := GetCurrentGRPCAndHTTPPort(t)

	createNegativeTestFlow := func(flowDescription string, componentSuffix string, initErrorCodes ...string) {
		componentPath := filepath.Join(secretStoreComponentPathBase, componentSuffix)
		componentName := "my-hashicorp-vault-TestTokenAndTokenMountPath-" + componentSuffix

		// // capture log
		// logCaptor := &bytes.Buffer{}
		// runtimeLogger := logger.NewLogger("dapr.runtime")
		// runtimeLogger.SetOutput(io.MultiWriter(os.Stdout, logCaptor))

		// grepComponentInitError := func(capturedLog *bytes.Buffer) (string, error) {
		// 	target := []byte("INIT_COMPONENT_FAILURE")
		// 	scanner := bufio.NewScanner(capturedLog)
		// 	for scanner.Scan() {
		// 		if err := scanner.Err(); err != nil {
		// 			return "", err
		// 		}
		// 		if bytes.Contains(scanner.Bytes(), target) {
		// 			return scanner.Text(), nil
		// 		}
		// 	}
		// 	return "", scanner.Err()
		// }

		// assertComponentFailedToInitialize := func(ctx flow.Context) error {
		// 	defer logCaptor.Reset() // Just in case... would be better to runtimeLogger.SetOutput(os.Stdout)

		// 	errorLine, err := grepComponentInitError(logCaptor)
		// 	if err != nil {
		// 		return err
		// 	}

		// 	ctx.Logf("👀 errorLine: %s", errorLine)

		// 	assert.NotEmpty(t, errorLine)

		// 	return err
		// }

		// verifyComponentInitializationFailedWithMessage

		flow.New(t, flowDescription).
			Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
			Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
			Step(sidecar.Run(sidecarName,
				embedded.WithoutApp(),
				embedded.WithComponentsPath(componentPath),
				embedded.WithDaprGRPCPort(currentGrpcPort),
				embedded.WithDaprHTTPPort(currentHttpPort),
				componentRuntimeOptions(),
			)).
			Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
			// Due to https://github.com/dapr/dapr/issues/5487 we cannot perform negative tests
			// for the component presence against the metadata registry.
			// Instead we do a simpler negative test by ensuring a good key cannot be found
			Step("🛑Verify component is NOT registered",
				testComponentIsNotWorking(t, componentName, currentGrpcPort)).
			// Step("Verify error output", assertComponentFailedToInitialize).
			Step("Verify initialization error reported for component", assertInitializationFailedWithErrorsForComponent(componentName, initErrorCodes...)).
			Step("Bug depending behavior - test component is actually registered", testComponentFound(t, componentName, currentGrpcPort)).
			Run()
	}

	createPositiveTestFlow := func(flowDescription string, componentSuffix string) {
		componentPath := filepath.Join(secretStoreComponentPathBase, componentSuffix)
		componentName := "my-hashicorp-vault-TestTokenAndTokenMountPath-" + componentSuffix

		flow.New(t, flowDescription).
			Step(dockercompose.Run(dockerComposeProjectName, dockerComposeClusterYAML)).
			Step("Waiting for component to start...", flow.Sleep(5*time.Second)).
			Step(sidecar.Run(sidecarName,
				embedded.WithoutApp(),
				embedded.WithComponentsPath(componentPath),
				embedded.WithDaprGRPCPort(currentGrpcPort),
				embedded.WithDaprHTTPPort(currentHttpPort),
				componentRuntimeOptions(),
			)).
			Step("Waiting for component to load...", flow.Sleep(5*time.Second)).
			Step("✅Verify component is registered", testComponentFound(t, componentName, currentGrpcPort)).
			Step("Verify no errors regarding component initialization", assertNoInitializationErrorsForComponent(componentPath)).
			Step("Test that the default secret is found", testDefaultSecretIsFound(t, currentGrpcPort, componentName)).
			Run()
	}

	// createNegativeTestFlow("Verify failure when BOTH vaultToken and vaultTokenMountPath are present", "both", "token mount path and token both set")

	// createNegativeTestFlow("Verify failure when NEITHER vaultToken nor vaultTokenMountPath are present", "neither")

	createNegativeTestFlow("Verify failure when vaultToken value does not match our servers's value", "badVaultToken")

	// createNegativeTestFlow("Verify failure when vaultTokenPath points to a non-existing file", "tokenMountPathPointsToBrokenPath")

	createPositiveTestFlow("Verify success when vaultTokenPath points to an existing file matching the configured secret we have for our secret seeder", "tokenMountPathHappyCase")
}

//
// Aux. functions
//

func testKeyValuesInSecret(t *testing.T, currentGrpcPort int, secretStoreName string, secretName string, keyValueMap map[string]string) flow.Runnable {
	return func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		emptyOpt := map[string]string{}

		res, err := client.GetSecret(ctx, secretStoreName, secretName, emptyOpt)
		assert.NoError(t, err)
		assert.NotNil(t, res)

		for key, valueExpected := range keyValueMap {
			valueInSecret, exists := res[key]
			assert.True(t, exists, "expected key not found in key")
			assert.Equal(t, valueExpected, valueInSecret)
		}
		return nil
	}
}

func testSecretIsNotFound(t *testing.T, currentGrpcPort int, secretStoreName string, secretName string) flow.Runnable {
	return func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		emptyOpt := map[string]string{}

		_, err = client.GetSecret(ctx, secretStoreName, secretName, emptyOpt)
		assert.Error(t, err)

		return nil
	}
}

func testDefaultSecretIsFound(t *testing.T, currentGrpcPort int, secretStoreName string) flow.Runnable {
	return testKeyValuesInSecret(t, currentGrpcPort, secretStoreName, "multiplekeyvaluessecret", map[string]string{
		"first":  "1",
		"second": "2",
		"third":  "3",
	})
}

func testComponentIsNotWorking(t *testing.T, targetComponentName string, currentGrpcPort int) flow.Runnable {
	// TODO(tmacam) once https://github.com/dapr/dapr/issues/5487 is fixed, remove/replace with testComponentNotFound
	return testSecretIsNotFound(t, currentGrpcPort, targetComponentName, "multiplekeyvaluessecret")
}

// func testComponentNotFoundAndDefaultKeysFail(t *testing.T, targetComponentName string, currentGrpcPort int) flow.Runnable {
// 	return func(ctx flow.Context) error {
// 		// Due to https://github.com/dapr/dapr/issues/5487 we cannot perform negative tests
// 		// for the component presence against the metadata registry.
// 		// if err := testComponentNotFound(t, targetComponentName, currentGrpcPort)(ctx); err != nil {
// 		// 	return err
// 		// }

// 		// Instead we just check that the component fail queries for known the default secret
// 		if err := testSecretIsNotFound(t, currentGrpcPort, "multiplekeyvaluessecret")(ctx); err != nil {
// 			return err
// 		}
// 		return nil
// 	}
// }

func testComponentFound(t *testing.T, targetComponentName string, currentGrpcPort int) flow.Runnable {
	return testComponentPresence(t, targetComponentName, currentGrpcPort, true)
}

// Due to https://github.com/dapr/dapr/issues/5487 we cannot perform negative tests
// for the component presence against the metadata registry.
// func testComponentNotFound(t *testing.T, targetComponentName string, currentGrpcPort int) flow.Runnable {
// 	return testComponentPresence(t, targetComponentName, currentGrpcPort, false)
// }

func testComponentPresence(t *testing.T, targetComponentName string, currentGrpcPort int, expectedComponentFound bool) flow.Runnable {
	return func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		clientCtx := context.Background()

		resp, err := client.GrpcClient().GetMetadata(clientCtx, &empty.Empty{})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.GetRegisteredComponents())

		// Find the component
		componentFound := false
		for _, component := range resp.GetRegisteredComponents() {
			if component.GetName() == targetComponentName {
				ctx.Logf("🩺 component found=%s", component)

				componentFound = true
				break
			}
		}

		if expectedComponentFound {
			assert.True(t, componentFound, "Component was expected to be found but it was missing.")
		} else {
			assert.False(t, componentFound, "Component was expected to be missing but it was found.")
		}

		return nil
	}
}

func testComponentDoesNotHaveFeature(t *testing.T, currentGrpcPort int, targetComponentName string, targetCapability secretstores.Feature) flow.Runnable {
	return testComponentAndFeaturePresence(t, currentGrpcPort, targetComponentName, targetCapability, false)
}

func testComponentHasFeature(t *testing.T, currentGrpcPort int, targetComponentName string, targetCapability secretstores.Feature) flow.Runnable {
	return testComponentAndFeaturePresence(t, currentGrpcPort, targetComponentName, targetCapability, true)
}

func testComponentAndFeaturePresence(t *testing.T, currentGrpcPort int, targetComponentName string, targetCapability secretstores.Feature, expectedToBeFound bool) flow.Runnable {
	return func(ctx flow.Context) error {
		client, err := client.NewClientWithPort(fmt.Sprint(currentGrpcPort))
		if err != nil {
			panic(err)
		}
		defer client.Close()

		clientCtx := context.Background()

		resp, err := client.GrpcClient().GetMetadata(clientCtx, &empty.Empty{})
		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.NotNil(t, resp.GetRegisteredComponents())

		// Find the component
		var capabilities []string = []string{}
		for _, component := range resp.GetRegisteredComponents() {
			if component.GetName() == targetComponentName {
				capabilities = component.GetCapabilities()
				break
			}
		}

		if expectedToBeFound {
			assert.NotEmpty(t, capabilities)
		}

		// Find capability
		targetCapabilityAsString := string(targetCapability)
		capabilityFound := false
		for _, cap := range capabilities {
			if cap == targetCapabilityAsString {
				capabilityFound = true
				break
			}
		}
		assert.Equal(t, expectedToBeFound, capabilityFound)

		return nil
	}
}

func componentRuntimeOptions() []runtime.Option {
	log := logger.NewLogger("dapr.components")

	secretStoreRegistry := secretstores_loader.NewRegistry()
	secretStoreRegistry.Logger = log
	secretStoreRegistry.RegisterComponent(vault.NewHashiCorpVaultSecretStore, "hashicorp.vault")

	return []runtime.Option{
		runtime.WithSecretStores(secretStoreRegistry),
	}
}

func GetCurrentGRPCAndHTTPPort(t *testing.T) (int, int) {
	ports, err := dapr_testing.GetFreePorts(2)
	assert.NoError(t, err)

	currentGrpcPort := ports[0]
	currentHttpPort := ports[1]

	return currentGrpcPort, currentHttpPort
}
