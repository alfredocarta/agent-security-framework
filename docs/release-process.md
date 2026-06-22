# Release Process — ASF

This document describes the intended signing and release process for ASF distribution.
It is specified here for completeness; execution is not required for the current prototype.

## Versioning

ASF follows semantic versioning: MAJOR.MINOR.PATCH.
- MAJOR: breaking changes to the pipeline interface or hook contract.
- MINOR: new stages, new wrapper commands, or significant behavior changes.
- PATCH: bug fixes and internal improvements with no interface change.

The current version is tracked in asf-wrapper/Cargo.toml (the `version` field).

## Release artifacts

Each release should produce:

1. A compiled Rust binary for the target platform (e.g. aarch64-apple-darwin for macOS
M-series).
2. A SHA-256 checksum file (asf-daemon.sha256) for the binary.
3. A GPG or Minisign signature over the checksum file.
4. A versioned archive of the Python pipeline (tar.gz or zip), excluding any confidential
   classifier internals as defined in docs/ip-boundary.md.

## Signing keys

Before the first public release:
- Generate a Minisign keypair. Store the private key offline or in a hardware token.
- Publish the public key in this repository (e.g. as minisign.pub in the root).
- Document the key fingerprint in this file once generated.

Public key fingerprint: (to be filled before first release)

## Release checklist

- [ ] Version bumped in Cargo.toml and any Python version file.
- [ ] CHANGELOG entry written for the new version.
- [ ] All tests pass on a clean build.
- [ ] Binary compiled with --release flag.
- [ ] SHA-256 checksum computed and verified.
- [ ] Checksum file signed with the release key.
- [ ] Artifacts uploaded to the release page with checksum and signature attached.
- [ ] Git tag created: git tag -s vMAJOR.MINOR.PATCH

## Update command

The asf-run update command (implemented in asf-wrapper) prints manual update instructions
rather than performing silent auto-update. This is intentional: unattended updates of a
security enforcement layer introduce supply-chain risk that outweighs the convenience gain.
