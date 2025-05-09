# frozen_string_literal: true

require "openssl"
require "tpm/key_attestation/version"

require "tpm/aik_certificate"
require "tpm/certify_validator"
require "tpm/constants"
require "tpm/public_area"

module TPM
  class KeyAttestation
    # https://docs.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates
    TRUSTED_CERTIFICATES =
      begin
        pattern = File.expand_path(File.join(__dir__, "certificates", "*", "RootCA", "*.*"))
        Dir.glob(pattern).map do |filename|
          file = File.binread(filename)
          OpenSSL::X509::Certificate.new(file)
        end
      end

    class Error < StandardError; end

    attr_reader(
      :certify_info,
      :signature,
      :certified_key,
      :certificates,
      :signature_algorithm,
      :hash_algorithm,
      :qualifying_data,
      :trusted_certificates
    )

    def initialize(
      certify_info,
      signature,
      certified_key,
      certificates,
      qualifying_data,
      signature_algorithm: ALG_RSASSA,
      hash_algorithm: ALG_SHA256,
      trusted_certificates: TRUSTED_CERTIFICATES
    )
      @certify_info = certify_info
      @signature = signature

      @certified_key = certified_key
      @certificates = certificates
      @signature_algorithm = signature_algorithm
      @hash_algorithm = hash_algorithm
      @qualifying_data = qualifying_data
      @trusted_certificates = trusted_certificates
    end

    def key
      if valid?
        public_area.key
      end
    end

    def valid?
      certify_validator.valid?(aik_certificate.public_key) &&
        aik_certificate.conformant? &&
        trustworthy?
    end

    private

    def certify_validator
      @certify_validator ||=
        TPM::CertifyValidator.new(
          certify_info,
          signature,
          qualifying_data,
          public_area,
          signature_algorithm: signature_algorithm,
          hash_algorithm: hash_algorithm
        )
    end

    def trustworthy?
      x509_certificates = certificates.map { |c| OpenSSL::X509::Certificate.new(c) }

      trust_store.verify(x509_certificates[0], x509_certificates[1..-1])
    end

    def trust_store
      @trust_store ||=
        OpenSSL::X509::Store.new.tap do |trust_store|
          trusted_certificates.uniq(&:serial).each { |trusted_certificate| trust_store.add_cert(trusted_certificate) }
        end
    end

    def aik_certificate
      @aik_certificate ||= TPM::AIKCertificate.from_der(certificates.first)
    end

    def public_area
      @public_area ||= TPM::PublicArea.new(certified_key)
    end
  end
end
