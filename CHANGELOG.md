# Changelog

## Unreleased

- Added opt-in, streaming AES-GCM support with arbitrary IV lengths, compact
  NIST CAVP vectors, authenticated tag verification, a block-wise update path,
  and configurable constant-time, wide, table-based, and hardware GHASH
  profiles. The default remains heap-free and constant-time, GCM-disabled
  builds retain no GCM context or runtime overhead, and each context rejects
  mixed encryption/decryption updates. Documented GCM usage, nonce and
  authentication requirements, in-place decryption precautions, profile
  trade-offs, and expanded the test matrix to cover all portable GHASH modes.
- Added configurable secure, runtime-generated, and fast S-box profiles plus
  portable opt-in wide operations for embedded targets.
- Made AES-128 the default only when no AES key-size macro is supplied, so
  AES192 and AES256 can be selected directly by the build.
- Added an exhaustive 126-configuration Make/CMake test matrix covering key
  sizes, mode combinations, S-box profiles, and wide-operation settings.
- Reworked the unit tests around vendored µunit (munit), added cross-platform
  CMake/CTest support, and organized the AES-128/192/256 NIST SP 800-38A
  Appendix F vectors into a shared test-vector header.
- Replaced secret-indexed AES S-box and inverse S-box lookups with fixed-size,
  masked scans so the table-access pattern is independent of the input byte.
