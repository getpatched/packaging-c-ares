# GetPatched recipe: c-ares

GetPatched maintains selected security backports for distribution packages whose normal security support has ended. This repository contains public source recipes, target-specific patches and bounded regression inputs. It does not contain a forked copy of c-ares; builds fetch the pinned distribution source package and retain its packaging and existing patches.

## Targets

| Target | Base source | GetPatched version | Runtime binary | Patch | State |
|---|---|---|---|---|---|
| Ubuntu 20.04 Focal, amd64 | `1.15.0-1ubuntu0.5` | `1.15.0-1ubuntu0.5+getpatched1` | `libc-ares2` | Expanded-name length bound | Hosted verification passed; sponsor flow pending; no binary published |
| Debian 13 Trixie, amd64 | `1.34.5-1+deb13u1` | `1.34.5-1+deb13u1+getpatched1` | `libcares2` | Expanded-name and pointer-hop bounds | Reverification pending after regression-boundary correction; no binary published |

Ubuntu's advisory identifies the Focal public source as affected by CVE-2026-69184; the distribution's Focal fix is in ESM. Its legacy `ares_expand_name.c` parser already limits pointer hops to 50, so the Trixie patch does not apply directly. The Focal backport adds the RFC 1035 255-octet expanded wire-name limit. The hosted run built the exact Focal source, passed the installed parser regression and normal consumer checks, removed the target CVE finding from the package-aware scan, and passed the signed APT-client check: [run 41492142682](https://github.com/getpatched/platform/actions/runs/41492142682).

Trixie uses the newer `ares_dns_name_parse()` implementation. The corrected candidate enforces the expanded wire-name limit and caps parser work at 1024 pointer hops, with coverage for an adversarial 1100-hop chain and a valid 200-hop compatibility control. The previous hosted run tested an earlier candidate and is not evidence for this recipe. A new exact-source build, installed regressions, package-aware scan, consumer checks and signed APT-client check are required before it is counted. The isolated build uses a loopback-only resolver so the upstream timeout test is deterministic while network access remains disabled.

## Recipe structure

`package-manifest.json` indexes one recipe file per distribution, release and architecture. Each target file pins its exact source descriptor and archives, hashes, output version, binary packages, applicable patches and release policy. `patches/metadata.json` records target-specific applicability, upstream provenance and regression expectations. Focal's source metadata notes that signed Ubuntu source indexes and file hashes were verified, while source uploader signatures were not separately validated against a keyring.

The Focal C probe checks a bounded overlong-name case and the valid 255-octet boundary. The Trixie probe rejects a bounded 1100-hop backward pointer chain; the upstream parser tests also require a valid 200-hop chain, a maximum-valid 255-wire-octet name, and rejection at 256 octets. Neither probe attempts to measure resource exhaustion or exercise code execution.

## Sponsorship and licenses

Both binaries are configured as sponsor-first for 168 hours after sponsor publication. The sponsor entitlement, revocation and promotion flow is not yet validated, so these verified candidates are not release-eligible and no production binary has been published. All recipe source and patches are public from day one. Every active individual GitHub Sponsors tier is intended to get early binary access; early binaries may be used privately and commercially, but redistribution is prohibited until public promotion. Access ends when GitHub reports sponsorship inactive. GetPatched-authored material is MIT-licensed; c-ares and distribution source notices remain in force. See `LICENSES/GETPATCHED-EARLY-ACCESS-1.2.md`, `LICENSES/upstream-LICENSE.md`, and `LICENSES/debian-source-copyright`.

Builds use each target's exact distribution source archives, not an upstream submodule. Target support is specific to distribution, release and architecture. Adding another release or arm64 requires its own source pin, patch applicability, build, installed regression, scan and APT test.
