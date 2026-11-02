# GetPatched recipe: c-ares

GetPatched maintains selected security backports for distribution packages whose normal security support has ended. This repository contains the public source recipe, patch and reproducible regression input. It does not contain a forked copy of c-ares; builds fetch the pinned Debian source package and retain Debian's packaging and existing patches.

## Current target

| Field | Value |
|---|---|
| Target | Debian 13 (Trixie), amd64 |
| Source | `c-ares` `1.34.5-1+deb13u1` from the signed Trixie security source index |
| GetPatched version | `1.34.5-1+deb13u1+getpatched1` |
| Runtime binary | `libcares2` |
| Access | Sponsor first for 168 hours, then public after release checks |
| State | Development candidate; no release binary is published |

Debian Trixie's source predates c-ares 1.34.7, which contains the upstream fix. The five adapted upstream tests were run against the exact Trixie source on amd64: the vulnerable parser accepted four invalid overlong-name or pointer-chain cases; after the backport all five cases passed, including the valid maximum-boundary case. This is source-build evidence only; the complete Debian package build, installed-package regression, package-aware scan and clean APT install still need to pass before release.

The package currently targets Trixie only. Debian Bookworm is excluded because the security tracker says it does not contain the vulnerable modern DNS parser; Ubuntu Focal uses an older `ares_expand_name.c` implementation and remains unsupported until its applicability and a distinct backport are proven against that exact source.

## Structure and patch

`package-manifest.json` indexes target-specific recipe files. `targets/debian/trixie-amd64.json` pins the source version, Debian snapshot file identifiers, SHA-256 hashes, architecture, package version and release policy. `patches/metadata.json` declares the target-scoped patch, upstream commit, checksum and regression test. The patch `patches/CVE-2026-69184-trixie.patch` adapts upstream commit [`5c8341b`](https://github.com/c-ares/c-ares/commit/5c8341ba6ff3a8e4e4dfd616f8ed0418838b8b7) to Trixie's older test-file layout while bounding expanded DNS names and compression-pointer hops.

The checked-in C regression probe creates a bounded DNS packet with a 200-hop backward pointer chain. It reports only parser status and whether a record was returned. It does not attempt to measure resource exhaustion or exercise code execution. The patch also adds upstream parser tests for overlong names and pointer chains.

## Sponsorship and licenses

All recipe source and patches are public from day one. For the official binary only, every active individual GitHub Sponsors tier gets access during the first seven days. Early binaries may be used privately and commercially; redistribution is prohibited until public promotion. Access ends when GitHub reports sponsorship inactive. GetPatched-authored material is MIT-licensed; c-ares and Debian source notices remain in force. See `LICENSES/GETPATCHED-EARLY-ACCESS-1.2.md`, `LICENSES/upstream-LICENSE.md`, and `LICENSES/debian-source-copyright`.

Builds use the exact Debian source archive, not an upstream submodule. Target support is specific to Debian release and architecture. Adding Ubuntu, another Debian release, or arm64 requires its own source pin, patch applicability, build, installed regression, scan and APT test.
