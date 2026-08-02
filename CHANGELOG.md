# Changelog

## Unreleased

- Replaced secret-indexed AES S-box and inverse S-box lookups with fixed-size,
  masked scans so the table-access pattern is independent of the input byte.
