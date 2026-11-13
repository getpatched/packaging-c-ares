# GetPatched recipe: c-ares

GetPatched maintains selected security backports for distribution packages whose normal security support has ended. This repository contains public source recipes, target-specific patches and bounded regression inputs. It does not contain a forked copy of c-ares; builds fetch the pinned distribution source package and retain its packaging and existing patches.

## Targets

| Target | Base source | GetPatched version | Binaries | Patch | State |
|---|---|---|---|---|---|
| Ubuntu 20.04 Focal, amd64 | `1.15.0-1ubuntu0.5` | `1.15.0-1ubuntu0.5+getpatched1` | `libc-ares2` | Expanded-name length bound | Hosted verification passed; sponsor flow pending; no binary published |
| Debian 13 Trixie, amd64 | `1.34.5-1+deb13u1` | `1.34.5-1+deb13u1+getpatched2` | `libcares2` | DNS name bounds; record-count preallocation bound | Development-verified; sponsor flow pending; no binary published |
| Debian 13 Trixie, amd64 | `1.34.5-1+deb13u1` | `1.34.5-1+deb13u1+getpatched3` | `libcares2`, `libc-ares-dev` | CVE-2026-33630 query completion | Unverified; remote route not reproduced; no binary published |

Ubuntu's advisory identifies the Focal public source as affected by CVE-2026-69184; the distribution's Focal fix is in ESM. Its legacy `ares_expand_name.c` parser already limits pointer hops to 50, so the Trixie patch does not apply directly. The Focal backport adds the RFC 1035 255-octet expanded wire-name limit. The hosted run built the exact Focal source, passed the installed parser regression and normal consumer checks, removed the target CVE finding from the package-aware scan, and passed the signed APT-client check: [run 41492142682](https://github.com/getpatched/platform/actions/runs/41492142682).

Trixie uses the newer `ares_dns_name_parse()` implementation. Its backport adds the pointer-hop cap and expanded-name bound with parser tests. The corrected CVE-2026-69184 verification passed against the installed candidate: [run 41681088396](https://github.com/getpatched/platform/actions/runs/41681088396). The isolated build uses a loopback-only resolver so the upstream timeout test is deterministic while network access remains disabled.

The Trixie source also backports the fix for CVE-2026-69186. It validates DNS answer, authority, and additional-record counts against the remaining message length before allocating record arrays. In the final hosted run, the exact installed baseline reproduced the malformed record-count allocation with a 15,728,936-byte Massif peak; candidate `1.34.5-1+deb13u1+getpatched2` rejected it and retained the valid DNS control with a 4,490-byte peak. The same candidate passed the pointer-chain regression for CVE-2026-69184. The package-aware target scan removed both c-ares CVEs; one unrelated Expat finding remains. Package build/tests, consumer checks, and an isolated signed APT-client/by-hash check passed: [run 41703193562](https://github.com/getpatched/platform/actions/runs/41703193562). The run retains the concise reports and full Trivy artifacts; this candidate is not described as Trivy-clean.

## Recipe structure

`package-manifest.json` indexes one recipe file per distribution, release and architecture. Each target file pins its exact source descriptor and archives, hashes, output version, binary packages, applicable patches and release policy. `patches/metadata.json` records target-specific applicability, upstream provenance and regression expectations. Focal's source metadata notes that signed Ubuntu source indexes and file hashes were verified, while source uploader signatures were not separately validated against a keyring.

The Focal C probe checks a bounded overlong-name case and the valid 255-octet boundary. The Trixie probes check a bounded 200-hop backward pointer chain, malformed record counts that previously caused disproportionate allocation, and valid DNS controls. The record-count regression measures peak heap to demonstrate the allocation reduction; neither probe exercises code execution.

## Sponsorship and licenses

Both binaries are configured as sponsor-first for 168 hours after sponsor publication. The sponsor entitlement, revocation and promotion flow is not yet validated, so these verified candidates are not release-eligible and no production binary has been published. All recipe source and patches are public from day one. Every active individual GitHub Sponsors tier is intended to get early binary access; early binaries may be used privately and commercially, but redistribution is prohibited until public promotion. Access ends when GitHub reports sponsorship inactive. GetPatched-authored material is MIT-licensed; c-ares and distribution source notices remain in force. See `LICENSES/GETPATCHED-EARLY-ACCESS-1.2.md`, `LICENSES/upstream-LICENSE.md`, and `LICENSES/debian-source-copyright`.

## Unverified Trixie CVE-2026-33630 candidate

A local unreleased candidate advances the Trixie package version to 1.34.5-1+deb13u1+getpatched3 and applies the zero-fuzz c-ares v1.34 fix for CVE-2026-33630. The target includes both `libcares2` and `libc-ares-dev`, which ships `libcares.a`; the runner compiles the same bounded installed regression once against the shared library and once against the static archive. Both linkages must reproduce the callback-triggered invalid free on the exact Trixie baseline and require single callback completion with clean Memcheck on the candidate. The fixture also exercises the advisory's remote `ares_getaddrinfo()` TCP sequence, but exact-source ASan runs on macOS ARM64 did not reproduce an invalid access in either baseline or patched variants. That is diagnostic only and does not validate the remote route or package. The candidate is unverified, has no hosted build or full package acceptance evidence, and no binary has been published.

A supplemental native macOS/ARM64 source check built `arestest` from the exact Trixie source plus the candidate patch; the upstream `CancelInCallbackNoDoubleFree` test passes for IPv4 and IPv6, and the standalone patched fixture reports one callback. The baseline standalone source process aborts during callback cancellation. This is source-only diagnostic evidence: it does not establish a Debian amd64 package build, installed patched regression, or any remaining acceptance gate. The separate remote `ares_getaddrinfo()` TCP route also remains unproven.
