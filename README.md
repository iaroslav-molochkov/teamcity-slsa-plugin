# TeamCity SLSA Plugin

A TeamCity server plugin that generates [SLSA v1.2 build provenance](https://slsa.dev/spec/v1.2/build-provenance)
for build artifacts. It signs the provenance with AWS KMS or a PEM private key stored on the server
and publishes it as `provenance.sigstore.json`, a Sigstore bundle containing a DSSE envelope.

The plugin generates and signs provenance on the server. Signing keys and credentials must be
kept separate from build agents.

## How it works

For a successful build with the **SLSA Provenance Attestation** build feature enabled, the plugin:

1. Computes SHA-256 digests of file artifacts visible in the server's default artifact view.
2. Records build inputs, dependencies, platform identity, and timestamps.
3. Signs the provenance and publishes the bundle as a build artifact.

Builds without file artifacts produce no attestation.

## Build and install

Requires TeamCity 2025.03 (build 186049) or later.

```bash
./gradlew clean test serverPlugin
```

To select the TeamCity API version, pass `-Pteamcity.version=2025.03`.

1. Upload the generated plugin zip under **Administration → Plugins → Upload plugin zip**.
2. Enable the plugin.
3. Add **SLSA Provenance Attestation** under the build configuration's **Build Features**.
4. Configure a signer using the [integration guide](docs/integration.md).

## Kotlin DSL

The build feature can also be configured in the `features` block of `settings.kts`:

```kotlin
slsaProvenance {
    signer = awsKms {
        region = "us-east-1"
        keyId = "arn:aws:kms:us-east-1:123456789012:key/abcd-…"
        signingAlgorithm = "ECDSA_SHA_256"
        credentials = defaultCredentials {}
    }
    assumeRole = true
    roleArn = "arn:aws:iam::123456789012:role/tc-slsa-signer"
    failBuildOnError = true
}
```

`assumeRole` and `failBuildOnError` are optional. Set `roleArn` when enabling `assumeRole`.
`failBuildOnError` makes provenance errors fail the build.
For a server key, use `signer = serverKey { keyName = "signing-key.pem" }`.

## Documentation

- [Integration guide](docs/integration.md): signer configuration, permissions, and verification.
- [Build type v1](docs/buildtype/v1.md): output fields, trust model, and limitations.
