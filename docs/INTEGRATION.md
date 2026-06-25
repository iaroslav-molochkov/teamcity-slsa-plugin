# Integration Guide

This guide explains how to configure the plugin to produce signed provenance for a build,
and how to verify that provenance afterwards. It assumes familiarity with operating
TeamCity and a command line, but no prior knowledge of supply-chain attestation. Terms are
defined on first use; a consolidated glossary appears in the final section.

---

## 1. Overview

The plugin attaches to a build configuration. When a build finishes successfully, the plugin,
running on the TeamCity server, performs the following:

1. Computes a cryptographic digest (a fixed-length fingerprint) of each published artifact.
2. Assembles a structured record describing what was built and how (the *provenance*).
3. Signs that record with a private key.
4. Publishes the signed record as a build artifact named `provenance.intoto.jsonl`.

The output is a single file that any party can later use to confirm that a given artifact
was produced by this build, and that the description has not been altered.

---

## 2. Prerequisites

- A TeamCity server with the plugin installed (see the project README for installation).
- Permission to edit the target build configuration.
- A signing key (see Section 4 for the options).
- The server's externally visible URL configured correctly (see Section 3).

---

## 3. Configure the server URL (required for correct output)

The provenance records the identity of the build platform as an absolute URL (for example,
`https://teamcity.example.com`). This value is read from the TeamCity **server URL**
setting, because at the moment a build finishes there is no incoming web request from which
to infer the address.

Set it under **Administration → Global Settings → Server URL** to the exact address users
reach the server at, including any context path (the URL path prefix some deployments are
served under). If this is wrong, the provenance will name the platform
incorrectly, which weakens its value to verifiers.

---

## 4. Choose a signer

A *signer* determines where the private signing key lives and how the server authenticates
to use it. Three options are available; for the AWS KMS signers, assuming an IAM role is an
optional modifier on top of the chosen base credentials (Section 6.4).

| Signer | Key location | Use when |
|---|---|---|
| **AWS KMS — default provider chain** | AWS KMS | The server runs in AWS with an instance/container role; no secrets stored in TeamCity. Recommended. |
| **AWS KMS — access key** | AWS KMS | Long-lived AWS access keys are the only option. Least preferred (see Section 8). |
| **Server key** | A PEM file on the server's disk | No cloud KMS is available. |

Definitions:

- **AWS KMS (Key Management Service):** an AWS service that holds a private key and performs
  signing on request. The private key never leaves AWS; the server sends a digest and
  receives a signature.
- **Asymmetric key:** a key pair consisting of a *private key* (used to sign; kept secret)
  and a *public key* (used to verify; safe to publish). KMS keys used here must be of type
  *asymmetric, SIGN_VERIFY*.
- **STS (Security Token Service):** an AWS service that issues temporary credentials. The
  *assume-role* signer uses it to obtain short-lived credentials scoped to the signing role.
- **PEM file:** a text file encoding a key. The *server key* signer reads a PEM private key
  from a path on the server's filesystem.

General guidance: prefer a key held in KMS over a key on disk, and prefer credentials that
are obtained dynamically (default chain, assume-role) over long-lived stored secrets.

---

## 5. Enable the build feature

1. Open the build configuration.
2. Go to **Build Features**.
3. Select **Add build feature**.
4. Choose **SLSA Provenance Attestation** from the list.

   - A *build feature* is an optional capability attached to a build configuration. Only one
     instance of this feature is permitted per configuration.

5. In the form, set **Signer** to the option chosen in Section 4. The form then shows only
   the fields relevant to that signer.
6. Fill in the signer-specific fields (Section 6).
7. Optionally enable **Fail build on error** (Section 7).
8. Save.

A field marked with an asterisk is required. The form validates required fields on save.

---

## 6. Signer-specific fields

### 6.1 Server key

| Field | Required | Meaning |
|---|---|---|
| Private key file | Yes | Absolute path, on the server, to a PEM private key (EC or RSA; PKCS#8, PKCS#1, or SEC1 format). The file should be readable only by the server process. |

Retain the matching public key; verifiers will need it. The plugin derives the key
identifier published in the signature as `sha256:<public key>` (see Section 9).

### 6.2 AWS KMS — default provider chain

| Field | Required | Meaning |
|---|---|---|
| AWS region | No | The region of the KMS key (for example, `us-east-1`). If omitted, the AWS SDK's own region resolution is used. |
| KMS key id / ARN | Yes | The asymmetric SIGN_VERIFY key: a key id, alias, or ARN (Amazon Resource Name, the fully qualified identifier of an AWS resource). |
| Signing algorithm | Yes | Must match the key's specification (for example, `ECDSA_SHA_256` for an `ECC_NIST_P256` key). |

Credentials are resolved by the AWS SDK's default *provider chain*: an ordered search of
environment variables, container/instance roles, and configuration files. No credentials are
stored in TeamCity.

### 6.3 AWS KMS — access key

All fields from Section 6.2, plus:

| Field | Required | Meaning |
|---|---|---|
| Access key id | Yes | The AWS access key identifier. |
| Secret access key | Yes | The corresponding secret. Stored encrypted by TeamCity. |

### 6.4 Assume an IAM role (optional)

Available with either AWS KMS signer. When enabled, the signer's base credentials — the default
provider chain (Section 6.2) or the static access key (Section 6.3) — are used to call STS and assume
the specified role, and the resulting temporary credentials perform the signing. When disabled, the
fields below are ignored.

| Field | Required | Meaning |
|---|---|---|
| Role ARN | Yes (when enabled) | The IAM role to assume before signing. It should be scoped to permit only `kms:Sign` on the signing key. |
| Session name | No | A label for the assumed-role session. Defaults to `teamcity-slsa-signer`. |
| External id | No | A shared value required by some cross-account role trust policies. |
| Session duration (s) | No | Lifetime of the temporary credentials, in seconds. |
| STS endpoint | No | An override for the STS endpoint (regional or VPC). |

---

## 7. Failure behaviour

By default, if provenance cannot be produced, the build still succeeds and a warning is
written to the build log. This is the *fail-open on the build, fail-closed on the
attestation* model: a problem never results in a published but incorrect attestation; it
results in no attestation plus a warning.

Enable **Fail build on error** to make a provenance failure fail the build instead. A
published attestation is always complete and well-formed regardless of this setting.

---

## 8. Run a build and locate the output

Run the build configuration. On successful completion, the build's **Artifacts** tab lists:

```
provenance.intoto.jsonl
```

This is the signed attestation. Download it for verification (Section 9). The format,
`.jsonl`, is JSON Lines: each line is a complete JSON document. This file contains a single
line: a *DSSE envelope* (defined below).

---

## 9. Verify the provenance

Verification answers two questions: *was the record altered?* and *who signed it?* It
requires the attestation file and the signer's public key.

Obtaining the public key:

- **Server key signer:** use the public key you retained when configuring the signer.
- **AWS KMS signers:** export the key once with
  `aws kms get-public-key --key-id <id>` and save it as a PEM file.

### 9.1 Concepts

- **DSSE envelope (Dead Simple Signing Envelope):** a JSON structure with three fields:
  `payload` (the record, encoded in Base64), `payloadType` (a label identifying the record
  format), and `signatures` (one or more signatures over the payload).
- **Base64:** a reversible text encoding of arbitrary bytes using only printable
  characters, so binary data can be embedded in JSON.
- **Payload:** once Base64-decoded, the human-readable provenance record (an *in-toto
  Statement*; see the glossary).
- **PAE (Pre-Authentication Encoding):** the exact byte sequence that was actually signed.
  It is not the file as stored, nor the payload alone; it is a defined concatenation of the
  payload type and payload, each prefixed by its length. The length prefixes make the
  encoding unambiguous, which prevents an attacker from reinterpreting the boundary between
  fields. Verification must reconstruct this sequence precisely.
- **Key identifier (`keyid`):** a fingerprint of the public key, published in the signature
  as `sha256:<public key>`. Recomputing it from a public key confirms which key a signature
  refers to.

### 9.2 Procedure

The following uses standard `python3` and `openssl`. Replace the filename as needed.

**Step 1 — reconstruct the signed bytes and extract the signature.**

The PAE is `DSSEv1`, then the length of the payload type, then the payload type, then the
length of the payload, then the payload, all separated by single spaces. The lengths are
byte counts of the decoded payload.

```bash
F="provenance.intoto.jsonl"
python3 -c "
import json, base64
e = json.load(open('$F'))
payload = base64.b64decode(e['payload'])
pt = e['payloadType'].encode()
pae = b'DSSEv1 ' + str(len(pt)).encode() + b' ' + pt + b' ' + str(len(payload)).encode() + b' ' + payload
open('pae.bin','wb').write(pae)
open('sig.bin','wb').write(base64.b64decode(e['signatures'][0]['sig']))
print('keyid:', e['signatures'][0]['keyid'])
"
```

This writes `pae.bin` (the signed bytes) and `sig.bin` (the signature), and prints the key
identifier stated in the file.

**Step 2 — verify the signature against the public key.**

```bash
openssl dgst -sha256 -verify pub.pem -signature sig.bin pae.bin
```

Expected output: `Verified OK`. Any other result means the record was altered or was not
signed by the private key matching `pub.pem`; the attestation must not be trusted.

**Step 3 — confirm the public key matches the stated key identifier.**

```bash
openssl pkey -pubin -in pub.pem -outform DER | openssl dgst -sha256 | sed 's/^.*= /sha256:/'
```

The printed value must equal the `keyid` from Step 1.

### 9.3 Establishing trust in the key

A successful verification proves the record is intact and was signed by the holder of a
specific key. It does not, by itself, prove that the key belongs to the build platform you
expect. That trust is established out of band:

- **AWS KMS:** confirm the key's ARN and AWS account are the ones you expect.
- **Server key:** trust the public key because of how you obtained it (you published it, or
  received it through a trusted channel).

A consumer should also confirm that the `builder.id` field inside the payload names the
expected platform, and should base any policy decisions only on the `externalParameters`
section (`internalParameters` are platform-assigned and not intended for security decisions).

---

## 10. Glossary


- **Artifact:** a file produced by a build and published by TeamCity.
- **Attestation:** a signed, machine-readable statement about an artifact.
- **builder.id:** a field in the provenance giving the absolute URL that identifies the
  build platform. Used by verifiers as the trust anchor.
- **DSSE envelope:** the signed container format (see Section 9.1).
- **Digest:** a fixed-length fingerprint of data, here SHA-256, such that any change to the
  data changes the digest.
- **externalParameters / internalParameters:** two sections of the provenance.
  `externalParameters` are requester-controlled inputs that a verifier may rely on;
  `internalParameters` are platform-assigned values intended for debugging only.
- **in-toto Statement:** the standard structure of the payload, comprising a `subject`
  (the artifacts, by name and digest) and a `predicate` (the provenance details: the
  `buildDefinition` describing inputs, and the `runDetails` describing the execution).
- **Provenance:** a record of how an artifact was produced.
- **SLSA (Supply-chain Levels for Software Artifacts):** a specification defining the
  contents and assurances of build provenance. This plugin produces SLSA v1.0 provenance.
- **Signer:** the configured choice of signing key location and credential method
  (Section 4).
