# Integration Guide

This guide explains how to configure the plugin to produce signed provenance for a build,
and how to verify that provenance afterwards. A glossary appears in the final section.

## 1. Overview

The plugin attaches to a build configuration. When a build finishes successfully, the plugin,
running on the TeamCity server, performs the following:

1. Computes a SHA-256 digest of each file artifact visible in the server's default artifact view.
2. Records build inputs, dependencies, platform identity, and timestamps in the provenance.
3. Signs that record with a private key.
4. Publishes the signed record as the build artifact `provenance.sigstore.json` — a Sigstore
   bundle, verifiable with `cosign`.

Consumers can verify the signature and match an artifact to its recorded digest. Trust in the
build information depends on trust in the signing key and platform (Section 9.4).

## 2. Prerequisites

- A TeamCity server with the plugin installed (see the project README for installation).
- Permission to edit the target build configuration.
- A signing key (see Section 4 for the options).
- The server's externally visible URL configured correctly (see Section 3).

## 3. Configure the server URL (required for correct output)

Set **Administration → Global Settings → Server URL** to the server's externally visible URL,
for example `https://teamcity.example.com`. The plugin uses it to identify the platform in
`builder.id` and link to the build in `invocationId`.

URLs are resolved per project. A project's root-URL override changes its recorded platform
identity.

## 4. Choose a signer

A *signer* determines where the private signing key lives. Two are available:

| Signer | Key location | Use when |
|---|---|---|
| **AWS KMS** | AWS KMS | A cloud KMS is available. Recommended. |
| **Server key** | A PEM file in the server key store | No cloud KMS is available. |

For the AWS KMS signer you then choose a **credentials method** — how the server authenticates
to AWS — independently of the key itself:

| Credentials | Use when |
|---|---|
| **Default provider chain** | The server runs in AWS with an instance/container role; no secrets stored in TeamCity. Recommended. |
| **Static access key** | Long-lived AWS access keys are the only option. Least preferred (see Section 8). |

Assuming an IAM role is an optional modifier layered on top of *either* credentials method
(Section 6.3).

Definitions:

- **AWS KMS (Key Management Service):** an AWS service that holds a private key and performs
  signing on request. The private key never leaves AWS; the server sends a digest and
  receives a signature. Keys must be *asymmetric, SIGN_VERIFY*.
- **STS (Security Token Service):** an AWS service that issues temporary credentials. The
  *assume-role* option uses it to obtain short-lived credentials scoped to the signing role.
- **Server key store:** the directory the *server key* signer reads PEM private keys from,
  managed by the server administrator (Section 6.1).

## 5. Enable the build feature

1. Open the build configuration.
2. Go to **Build Features**.
3. Select **Add build feature**.
4. Choose **SLSA Provenance Attestation** from the list.
5. In the form, set **Signer** to the option chosen in Section 4. The form then shows only
   the fields relevant to that signer.
6. Fill in the signer-specific fields (Section 6).
7. Optionally enable **Fail build on error** (Section 7).
8. Optionally enable **Include custom build parameters** to record the build's requester-supplied custom
   parameters in the provenance. Declared secrets (password-typed, `secure:`-prefixed, or reported by
   a passwords provider) are dropped; plain parameters are published as-is, so do not put secrets in
   plain parameters.
9. Save.

Only one instance of this feature is permitted per configuration. Fields marked with an asterisk
are required and validated on save.

## 6. Signer-specific fields

### 6.1 Server key

Keys are read from the server key store: the directory
`<TeamCity data directory>/system/pluginData/slsa/keys`, managed by the server administrator.
Place PEM private key files there (EC, RSA, or Ed25519; PKCS#8 for any, plus PKCS#1/SEC1 for
RSA/EC), readable only by the server process. File names are restricted to letters, digits,
dots, hyphens, and underscores.

| Field | Required | Meaning |
|---|---|---|
| Signing key | Yes | A key from the server key store, selected by file name. |

Project administrators select a key from the store by name; the plugin never reads key
material from an arbitrary path. Retain the matching public key; verifiers will need it. The
plugin derives the key identifier published in the bundle as `sha256:<public key>` (see
Section 9).

### 6.2 AWS KMS

The KMS key fields, common to both credentials methods:

| Field | Required | Meaning |
|---|---|---|
| AWS region | No | The region of the KMS key (for example, `us-east-1`). If omitted, the AWS SDK resolves it from the environment (`AWS_REGION`, profile, or instance metadata). |
| Use FIPS endpoints | No | Use the AWS FIPS endpoints for KMS and STS. Off by default. |
| KMS key id / ARN | Yes | The asymmetric SIGN_VERIFY key: a key id, alias, or ARN (Amazon Resource Name, the fully qualified identifier of an AWS resource). |
| Signing algorithm | Yes | Must match the key's specification (for example, `ECDSA_SHA_256` for an `ECC_NIST_P256` key). Supported: ECDSA and RSA (PSS or PKCS#1 v1.5) with SHA-256/384/512. KMS's other specs (SM2, ML-DSA, Ed25519) are not offered. `cosign --key` verifies `ECDSA_SHA_256` and `RSASSA_PKCS1_V1_5_SHA_256` (Section 9.2); the SHA-384/512 variants and RSA-PSS require `openssl` (Section 9.3). |
| Credentials | Yes | The credentials method: **default provider chain** or **static access key**. |

**Default provider chain.** Credentials are resolved by the AWS SDK's default *provider chain*:
an ordered search of environment variables, container/instance roles, and configuration files.
No credentials are stored in TeamCity. No further fields.

**Static access key.** Adds:

| Field | Required | Meaning |
|---|---|---|
| Access key id | Yes | The AWS access key identifier. |
| Secret access key | Yes | The corresponding secret. Stored encrypted by TeamCity. |

**GovCloud and other partitions.** Set the region to a partition region (for example
`us-gov-west-1`) and supply the key as a partition ARN (`arn:aws-us-gov:kms:…`). The SDK resolves
the KMS and STS endpoints from the region; no endpoint override is needed.

**FIPS endpoints.** Enable **Use FIPS endpoints** to address the `-fips` KMS and STS endpoints for
the configured region. KMS publishes `kms-fips` endpoints in most commercial regions; STS publishes
`sts-fips` in the US regions, Canada, and GovCloud only. In a region without an `sts-fips` endpoint,
such as `eu-west-1`, this option works with the default provider chain and the static access key,
and fails when **Assume an IAM role** is also enabled. Alternatively, set
`AWS_USE_FIPS_ENDPOINT=true` (or `use_fips_endpoint=true` in the AWS profile) in the TeamCity
**server's** environment to apply FIPS endpoints server-wide.

**Custom endpoints.** The plugin has no endpoint override fields. For private/VPC routing or
testing, set the AWS SDK's endpoint variables in the TeamCity **server's** environment (for
example, `AWS_ENDPOINT_URL_STS` and `AWS_ENDPOINT_URL_KMS`, or the `aws.endpointUrlSts` and
`aws.endpointUrlKms` JVM system properties). These apply to every AWS SDK client in the server
process.

**Permissions.** The signing identity needs `kms:Sign` on the key. With assume-role, the base identity
also needs `sts:AssumeRole` on the signing role. Verifiers need `kms:GetPublicKey` to export the public
key; the plugin does not require it. Use a dedicated signing identity with only the permissions it needs.

### 6.3 Assume an IAM role (optional)

Available with the AWS KMS signer under either credentials method. When enabled, the chosen base
credentials — the default provider chain or the static access key — are used to call STS and assume
the specified role, and the resulting temporary credentials perform the signing. When disabled, the
fields below are ignored.

| Field | Required | Meaning |
|---|---|---|
| Role ARN | Yes (when enabled) | The IAM role to assume before signing. It should be scoped to permit only `kms:Sign` on the signing key. |
| Session name | No | A label for the assumed-role session. Defaults to `teamcity-slsa-signer`. |
| External id | No | A shared value required by some cross-account role trust policies. |
| Session duration (s) | No | Lifetime of the temporary credentials, in seconds. |

## 7. Failure behaviour

If provenance generation or publication fails, the plugin writes a warning to the build log.
Enable **Fail build on error** to fail the build instead. This option is off by default.

Only complete attestations are published. A failed operation must not leave a partial attestation.

## 8. Run a build and locate the output

Run the build configuration. After provenance is generated, the build's **Artifacts** tab lists:

```
provenance.sigstore.json
```

Builds without file artifacts produce no attestation. Download the bundle and verify it with
`cosign` (Section 9.2) or `openssl` (Section 9.3).

## 9. Verify the provenance

Verification requires the attestation file and the signer's public key.

Obtaining the public key:

- **Server key signer:** use the public key you retained when configuring the signer.
- **AWS KMS signers:** export the key once. `get-public-key` returns DER in a JSON field, so
  convert it to PEM:

  ```bash
  aws kms get-public-key --key-id <id> --output text --query PublicKey \
    | base64 -d | openssl pkey -pubin -inform DER -outform PEM > pub.pem
  ```

### 9.1 Concepts

- **DSSE envelope (Dead Simple Signing Envelope):** a JSON structure with three fields:
  `payload` (the record, encoded in Base64), `payloadType` (a label identifying the record
  format), and `signatures` (one or more signatures over the payload).
- **Payload:** once Base64-decoded, the provenance record (an *in-toto Statement*; see the
  glossary).
- **PAE (Pre-Authentication Encoding):** the exact byte sequence that was signed — not the file
  as stored, nor the payload alone, but a defined concatenation of the payload type and payload,
  each prefixed by its length. Verification must reconstruct it precisely (Section 9.3).
- **Key identifier:** an identifier of the signing key, carried in the bundle as
  `verificationMaterial.publicKey.hint`. For the server key it is `sha256:<public key>` (a
  fingerprint you can recompute from the public key to confirm the match); for AWS KMS it is
  the key's ARN.
- **Sigstore bundle:** the JSON container this plugin publishes. It holds the DSSE envelope
  (`dsseEnvelope`) and the key reference (`verificationMaterial`), and is what `cosign`
  consumes directly.

### 9.2 Verify with cosign

`provenance.sigstore.json` is a Sigstore bundle, so [`cosign`](https://github.com/sigstore/cosign)
verifies it directly with the signer's public key — no manual reconstruction.

```bash
cosign verify-blob-attestation \
  --key pub.pem \
  --bundle provenance.sigstore.json \
  --type slsaprovenance1 \
  --insecure-ignore-tlog \
  --digest <artifact-sha256> --digestAlg sha256
```

Expected output: `Verified OK`. The flags serve these purposes:

- `--type slsaprovenance1` — the predicate is SLSA provenance v1; without it cosign expects a
  `custom` predicate and rejects the bundle.
- `--insecure-ignore-tlog` — this plugin signs with your own key and deliberately uses **no**
  transparency log (no Rekor); the flag tells cosign not to require one. It does not weaken the
  cryptographic check.
- `--digest … --digestAlg sha256` — binds the verification to a specific artifact by matching
  its SHA-256 (e.g. `shasum -a 256 dist/app.jar`) against the attestation's `subject[]`. To
  verify the envelope alone, omit both and pass `--check-claims=false`.

cosign trusts the key you supply with `--key`; the bundle's `publicKey.hint` (the signer's key
id) is informational only. Establish trust in that key out of band (Section 9.4).

**Algorithm support.** `cosign --key` uses SHA-256 for every ECDSA key, whatever the curve, and
treats RSA as PKCS#1 v1.5 with SHA-256. It verifies ECDSA P-256, RSA PKCS#1 v1.5 with SHA-256, and
Ed25519 (KMS: `ECDSA_SHA_256`, `RSASSA_PKCS1_V1_5_SHA_256`). A P-384 or P-521 server key, which this
plugin signs with the curve-matched SHA-384 or SHA-512, and the KMS `ECDSA_SHA_384/512`,
`RSASSA_PSS_*` and `RSASSA_PKCS1_V1_5_SHA_384/512` algorithms are not verifiable this way; use
`openssl` (Section 9.3).

### 9.3 Verify with openssl

OpenSSL verifies the signature. Use Python 3 to extract it from the bundle and reconstruct
the DSSE signed bytes (PAE).

**Step 1 — prepare the files.**

Python script example (e.g. `extract.py`):

```python
import base64
import json
from pathlib import Path

bundle = json.loads(Path("provenance.sigstore.json").read_text())
envelope = bundle["dsseEnvelope"]
payload_type = envelope["payloadType"].encode("utf-8")
payload = base64.b64decode(envelope["payload"])

pae = b" ".join([
    b"DSSEv1",
    str(len(payload_type)).encode(),
    payload_type,
    str(len(payload)).encode(),
    payload,
])

Path("pae.bin").write_bytes(pae)
Path("sig.bin").write_bytes(base64.b64decode(envelope["signatures"][0]["sig"]))
print("Key identifier:", bundle["verificationMaterial"]["publicKey"]["hint"])
```

Run it once:

```bash
python3 extract.py
```

This creates `pae.bin` and `sig.bin` for the commands below and prints the bundle's key identifier.

**Step 2 — verify the signature against the public key.**

The exact command depends on the signing algorithm you configured: it fixes the **hash** (the
`_SHA_256` / `_384` / `_512` suffix) and, for RSA, the **padding** (PSS vs PKCS#1 v1.5). Unlike
`cosign`, `openssl` will not infer these — you must match them, because the bundle does not
carry them (the algorithm travels with the key, out of band). Use `-sha384` / `-sha512` in place
of `-sha256` below when your algorithm ends in `384` / `512`.

*ECDSA* (e.g. `ECDSA_SHA_256`) — the hash matches the curve (P-256 → SHA-256):

```bash
openssl dgst -sha256 -verify pub.pem -signature sig.bin pae.bin
```

*RSA PKCS#1 v1.5* (e.g. `RSASSA_PKCS1_V1_5_SHA_256`) — same form; PKCS#1 v1.5 is openssl's
default padding:

```bash
openssl dgst -sha256 -verify pub.pem -signature sig.bin pae.bin
```

*RSA-PSS* (e.g. `RSASSA_PSS_SHA_256`) — PSS must be requested explicitly, with a salt length
equal to the digest length (the convention AWS KMS uses); the MGF1 hash matches the digest:

```bash
openssl dgst -sha256 -verify pub.pem -signature sig.bin pae.bin \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest
```

*Ed25519* (server-key signer only) — a one-shot signature over the whole message, with no
separate hash step, so `dgst` does not apply; verify the raw bytes with `pkeyutl`:

```bash
openssl pkeyutl -verify -pubin -inkey pub.pem -rawin -in pae.bin -sigfile sig.bin
```

Expected output: `Verified OK` (for the `dgst` forms) or `Signature Verified Successfully` (for
the Ed25519 `pkeyutl` form). Any other result means the record was altered, was not signed by the
private key matching `pub.pem`, **or** the hash/padding above does not match the algorithm the
signer used. With the wrong hash or padding a genuine signature fails to verify, so confirm those
before concluding the attestation is bad.

**Step 3 — confirm the public key matches the stated key identifier (server key).**

For the server key, the key id is `sha256:<public key>` and you can recompute it:

```bash
openssl pkey -pubin -in pub.pem -outform DER | openssl dgst -sha256 | sed 's/^.*= /sha256:/'
```

The printed value must equal the `keyid` from Step 1. (For AWS KMS the key id is the key's
ARN; confirm it identifies the key and account you expect — see Section 9.4.)

**Step 4 — confirm the artifact you care about is covered.**

The attestation covers file artifacts visible in the server's default artifact view, listed under
`subject[]`. To confirm a specific artifact is attested, compute its SHA-256 and check that it
appears as a subject digest:

```bash
shasum -a 256 dist/app.jar
python3 -c "import json,base64; print('\n'.join(s['digest']['sha256'] for s in json.loads(base64.b64decode(json.load(open('provenance.sigstore.json'))['dsseEnvelope']['payload']))['subject']))"
```

The artifact's digest must be among the printed subject digests. A signature that verifies but
does not list your artifact attests a different set of files.

### 9.4 Establishing trust in the key

A successful verification proves the record is intact and was signed by the holder of a
specific key. It does not, by itself, prove that the key belongs to the build platform you
expect. That trust is established out of band:

- **AWS KMS:** confirm the key's ARN and AWS account are the ones you expect.
- **Server key:** trust the public key because of how you obtained it (you published it, or
  received it through a trusted channel).

A consumer should also confirm that the `builder.id` field inside the payload names the
expected platform. Apply policy to the recorded inputs and build metadata as described in the
[trust model](buildtype/v1.md#trust-model).

## 10. Glossary

- **Artifact:** a file produced by a build and published by TeamCity.
- **Attestation:** a signed, machine-readable statement about an artifact.
- **builder.id:** a field in the provenance giving the absolute URL that identifies the
  build platform, resolved per project from the server URL.
- **DSSE envelope:** the signed container format (see Section 9.1).
- **Digest:** a fixed-length fingerprint of data, here SHA-256, used to detect changes to the data.
- **externalParameters / internalParameters:** two sections of the provenance.
  `externalParameters` are requester-supplied inputs (untrusted; a verifier checks them);
  `internalParameters` contain build metadata reported by the platform.
- **in-toto Statement:** the standard structure of the payload, comprising a `subject`
  (the artifacts, by name and digest) and a `predicate` (the provenance details: the
  `buildDefinition` describing inputs, and the `runDetails` describing the execution).
- **Provenance:** a record of how an artifact was produced.
- **SLSA (Supply-chain Levels for Software Artifacts):** a specification defining the
  contents and assurances of build provenance. This plugin produces SLSA v1 build provenance
  (per the SLSA v1.2 spec; the `…/provenance/v1` predicate shape is shared across v1.0–v1.2).
- **Signer:** the configured choice of signing key location and credential method
  (Section 4).
