# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-05

### Added

- Initial release. Generates SLSA v1.2 provenance for a finished build's artifacts and signs it as
  a DSSE envelope, published as a Sigstore bundle (`provenance.sigstore.json`) verifiable with
  `cosign verify-blob-attestation`.
- Signers: AWS KMS (default provider chain or static access key, optional assume-role) and a
  server-local PEM key (EC, RSA, or Ed25519).
- Typed Kotlin DSL extension (`slsaProvenance`).
- Build type contract `v1` (`docs/buildtype/v1.md`).
- Minimum supported TeamCity version: 2025.03 (build 186049).

[1.0.0]: https://github.com/iaroslav-molochkov/teamcity-slsa-plugin/releases/tag/v1.0.0
