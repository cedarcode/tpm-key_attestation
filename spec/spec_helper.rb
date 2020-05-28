# frozen_string_literal: true

require "bundler/setup"
require "tpm/key_attestation"
require "byebug"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def create_rsa_key
  key_bits = 1024 # NOTE: Use 2048 or more in real life. This choice is just for fast test runs.

  OpenSSL::PKey::RSA.new(key_bits)
end

def create_certificate(key, root_certificate, root_key)
  certificate = OpenSSL::X509::Certificate.new
  certificate.version = 2
  certificate.subject = OpenSSL::X509::Name.parse("")
  certificate.issuer = root_certificate.subject
  certificate.not_before = Time.now
  certificate.not_after = Time.now + 120
  certificate.public_key = key

  certificate_basic_constraints = "CA:FALSE"
  certificate_extended_key_usage = "2.23.133.8.3"
  certificate_san_critical = true
  certificate_san_manufacturer = "id:4E544300"
  certificate_san_model = "TPM test model"
  certificate_san_version = "id:42"

  extension_factory = OpenSSL::X509::ExtensionFactory.new
  extension_factory.config = OpenSSL::Config.parse(<<~OPENSSL_CONF)
    [dir_seq]
    seq = EXPLICIT:4,SEQUENCE:dir_seq_seq

    [dir_seq_seq]
    set = SET:dir_set

    [dir_set]
    seq.1 = SEQUENCE:dir_seq_1
    seq.2 = SEQUENCE:dir_seq_2
    seq.3 = SEQUENCE:dir_seq_3

    [dir_seq_1]
    oid=OID:2.23.133.2.1
    str=UTF8:"#{certificate_san_manufacturer}"

    [dir_seq_2]
    oid=OID:2.23.133.2.2
    str=UTF8:"#{certificate_san_model}"

    [dir_seq_3]
    oid=OID:2.23.133.2.3
    str=UTF8:"#{certificate_san_version}"
  OPENSSL_CONF

  certificate.extensions = [
    extension_factory.create_extension("basicConstraints", certificate_basic_constraints, true),
    extension_factory.create_extension("extendedKeyUsage", certificate_extended_key_usage),
    extension_factory.create_extension("subjectAltName", "ASN1:SEQUENCE:dir_seq", certificate_san_critical),
  ]

  certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

  certificate
end

def create_root_certificate(key)
  certificate = OpenSSL::X509::Certificate.new
  common_name = "Root-#{rand(1_000_000)}"

  certificate.subject = OpenSSL::X509::Name.new([["CN", common_name]])
  certificate.issuer = certificate.subject
  certificate.public_key = key
  certificate.not_before = Time.now
  certificate.not_after = Time.now + 60

  extension_factory = OpenSSL::X509::ExtensionFactory.new
  extension_factory.subject_certificate = certificate
  extension_factory.issuer_certificate = certificate

  certificate.extensions = [
    extension_factory.create_extension("basicConstraints", "CA:TRUE", true),
    extension_factory.create_extension("keyUsage", "keyCertSign,cRLSign", true),
  ]

  certificate.sign(key, OpenSSL::Digest::SHA256.new)

  certificate
end
