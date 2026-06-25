# teamcity-slsa-plugin

A **server-side** TeamCity plugin that generates [SLSA v1.0](https://slsa.dev) provenance for a
build's artifacts and signs it as a [DSSE](https://github.com/secure-systems-lab/dsse) envelope. The
signed attestation is published back onto the build as a downloadable artifact.

Everything happens on the TeamCity **server**: artifacts are read via the server `BuildArtifacts`
API, and signing is performed server-side with a key the build agents never see. Because the
provenance is produced by the platform (not the build steps) and the signing material is never
exposed to the build, the attestation cannot be forged by the build itself — the property associated
with SLSA Build **L2**, and the design goal behind L3's non-falsifiability. (Asserting L3 is a
platform-level assessment beyond this plugin.)

Signing can use **AWS KMS** (the key never leaves KMS) or a **PEM private key on the server's disk**.

## How it works

1. Add the **SLSA Provenance Attestation** build feature to a build configuration and choose a signer
   (see below).
2. When a build finishes successfully, `ProvenanceService` (driven by `ArtifactProvenanceListener`)
   orchestrates the steps below.
3. `ArtifactHasher` reads the build's file artifacts server-side (`VIEW_DEFAULT`) and SHA-256s each.
4. `ProvenanceBuilder` assembles an in-toto Statement v1 with a SLSA provenance predicate
   (build type, external/internal parameters, VCS revisions and upstream builds, builder id,
   timestamps).
5. The selected `SigningHandler` signs the DSSE PAE (`DsseService`) — for KMS via `kms:Sign`
   (`MessageType.DIGEST`), for the server key via local crypto — and wraps the result in a DSSE
   envelope.
6. `ProvenancePublisher` writes it to the build's artifacts as `provenance.intoto.jsonl` and indexes
   its metadata.

The output format is defined by the published build-type contract,
[`docs/buildtype/v1.md`](docs/buildtype/v1.md). For step-by-step setup and verification, see
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Configuring the build feature

Pick a **Signer**; the form then shows only the relevant fields.

| Signer | Key location | Notes |
| --- | --- | --- |
| **AWS KMS — default provider chain** | AWS KMS | Credentials from the SDK default chain (env/profile/container/instance role on the server). Recommended. |
| **AWS KMS — assume an IAM role** | AWS KMS | Server assumes a `kms:Sign`-scoped role via STS (temporary credentials). |
| **AWS KMS — access key** | AWS KMS | Long-lived access key id + secret (secret stored encrypted). Least preferred. |
| **Server key** | PEM file on the server | Absolute path to an EC/RSA PEM (PKCS#8, PKCS#1, or SEC1). |

For the KMS signers: **KMS key id / ARN** (an asymmetric `SIGN_VERIFY` key) and **signing
algorithm** (must match the key spec, e.g. `ECDSA_SHA_256`) are required; **AWS region** is required
except for the default provider chain. **Fail build on error** (off by default) turns a provenance
failure from a warning into a build failure.

The feature is exported to the **Kotlin DSL**, so it can be set in `settings.kts`:

```kotlin
feature {
    type = "slsa.provenance"
    param("slsa.signer", "aws-kms-default")
    param("slsa.aws.region", "us-east-1")
    param("slsa.kms.keyId", "arn:aws:kms:us-east-1:123456789012:key/abcd-…")
    param("slsa.kms.signingAlgorithm", "ECDSA_SHA_256")
    // optional: fail the build instead of warning
    param("slsa.failBuildOnError", "true")
}
```

For the server-key signer, set `slsa.signer` to `server` and `slsa.server.privateKeyPath` to the
absolute key path instead.

### Credentials, caching, and assume-role

KMS credential resolution uses the AWS SDK's own providers — `DefaultCredentialsProvider`,
`StaticCredentialsProvider`, or `StsAssumeRoleCredentialsProvider` (which refreshes the STS session
internally). `KmsClientCache` caches one client per **connection**, keyed (via `ConnectionIdService`)
on a hash of the signer type plus its identity fields (region, credentials identity, assume-role/STS
settings) — deliberately **not** on the KMS key id or the project. Builds that share a connection
reuse the client and its refreshed session credentials; evicted clients are closed.

The signing identity should be dedicated and least-privileged, and must not be shared with
credentials that are injected into build agents.

## Layout

| Path | Purpose |
| --- | --- |
| `feature/SlsaBuildFeature`, `SlsaEditFeatureController`, `config/SlsaParams` | The `slsa.provenance` build feature, its settings controller, and its parameter keys |
| `buildServerResources/editSlsaProvenanceFeature.jsp` | The feature's settings form (TeamCity taglibs) |
| `provenance/ProvenanceBuilder` + `provenance/intoto`, `provenance/slsa` | In-toto/SLSA model records + Jackson serialization (`ProvenanceJsonHandler`) |
| `signing/dsse` (`DsseService`, `DsseEnvelope`) | DSSE PAE encoding and envelope |
| `signing/SigningService`, `SigningHandler`, `signing/kms/**`, `signing/server/**` | Signer dispatch and per-signer handlers/validators |
| `aws/client/KmsClientCache`, `SignerClient` | KMS client caching and lifecycle |
| `core/ArtifactHasher`, `ProvenanceService`, `ArtifactProvenanceListener` | Artifact hashing and the build → sign → publish orchestration on `buildFinished` |
| `persist/ProvenancePublisher` | Publishes the artifact and indexes metadata |

Spring wiring is annotation-driven (`@Component` + `<context:component-scan>` in
`META-INF/build-server-plugin-teamcity-slsa.xml`).

## Building

```bash
./gradlew clean test serverPlugin
```

The installable zip is written to `build/distributions/teamcity-slsa-plugin-<version>.zip` with the
AWS SDK + Jackson bundled under `server/lib` (isolated by `useSeparateClassloader`). Target a
different TeamCity API with `-Pteamcity.version=2024.12`.

## Installing

1. Build the zip.
2. In TeamCity: **Administration → Plugins → Upload plugin zip**.
3. Enable it (the descriptor allows runtime reload).
4. Add the **SLSA Provenance Attestation** feature to a build configuration and configure a signer.

After a build finishes, the signed attestation appears as the `provenance.intoto.jsonl` artifact, and
`SLSA:` summary lines are written to `teamcity-server.log`. To verify the envelope, see
[`docs/INTEGRATION.md`](docs/INTEGRATION.md) (Section 9).

> **Server URL:** the provenance records the platform identity from **Administration → Global
> Settings → Server URL**. Set it to the externally visible address (including any context path) so
> `builder.id` and `invocationId` are correct.

## IAM (KMS signers)

The resolved identity needs `kms:Sign` on the key. For assume-role, the base identity needs
`sts:AssumeRole` on the signing role, and the signing role holds `kms:Sign`. Verifiers fetch the
public key once via `kms:GetPublicKey` (no permission needed by the plugin itself).
