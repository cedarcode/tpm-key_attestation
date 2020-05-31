# Changelog

## [v0.9.0] - 2020-05-31

### Fixed

- Fixed compatibility with OpenSSL-C (libssl) v1.0.2 ([@santiagorodriguez96])

## [v0.8.0] - 2020-03-29

### Changed

- Update `openssl-signature_algorithm` gem dependency from `v0.3` to `v0.4`.

## [v0.7.0] - 2020-02-25

### Added

- `TPM::KeyAttestation#valid?` performs certificate path validation. In other words, it verifies trust up
to an acceptable trusted root certificate.

### Changed

- Rename `TPM::EKCertificate` to `TPM::AIKCertificate` to fix semantics

## [v0.6.0] - 2020-01-30

### Changed

- `TPM::KeyAttestation.new` now accepts `signature_algorithm` and `hash_algorithm` in TPM format in
replacement of `JOSE` format `algorithm` string

## [v0.5.0] - 2020-01-23

### Added

- `TPM::KeyAttestation#valid?` also checks there's at least a well-formatted key in the attestation

## [v0.4.0] - 2020-01-20

### Added

- Suport verification of RSA-PSS key attestations

## [v0.3.0] - 2020-01-20

### Added

- `TPM::KeyAttestation#key` returns attested key as an instance of `OpenSSL::PKey::PKey`

## [v0.2.0] - 2020-01-16

### Added

- `TPM::KeyAttestation#valid?`

## [v0.1.0] - 2020-01-15

### Added

- `TPM::EKCertificate` wrapper
- `TPM::SAttest` wrapper

[v0.9.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.8.0...v0.9.0/
[v0.8.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.7.0...v0.8.0/
[v0.7.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.6.0...v0.7.0/
[v0.6.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.5.0...v0.6.0/
[v0.5.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.4.0...v0.5.0/
[v0.4.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.3.0...v0.4.0/
[v0.3.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.2.0...v0.3.0/
[v0.2.0]: https://github.com/cedarcode/tpm-key_attestation/compare/v0.1.0...v0.2.0/
[v0.1.0]: https://github.com/cedarcode/tpm-key_attestation/compare/57c926ef7e83830cee8d111fdc5ccaf99ab2e861...v0.1.0/

[@santiagorodriguez96]: https://github.com/santiagorodriguez96
