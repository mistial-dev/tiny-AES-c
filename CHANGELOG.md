# Changelog

## Unreleased

- Reworked the unit tests around vendored µunit (munit), added cross-platform
  CMake/CTest support, and organized the AES-128/192/256 NIST SP 800-38A
  Appendix F vectors into a shared test-vector header.
- Replaced secret-indexed AES S-box and inverse S-box lookups with fixed-size,
  masked scans so the table-access pattern is independent of the input byte.
