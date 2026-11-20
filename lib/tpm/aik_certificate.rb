# frozen_string_literal: true

require "delegate"
require "openssl"
require "tpm/constants"
require "tpm/openssl_helper"

module TPM
  # Section 3.2 in https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
  class AIKCertificate < SimpleDelegator
    ASN_V3 = 2
    EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze
    SAN_DIRECTORY_NAME = 4

    if TPM::OpenSSLHelper.running_openssl_version_35_or_up?
      OID_TCG_AT_TPM_MANUFACTURER = "tcg-at-tpmManufacturer"
      OID_TCG_AT_TPM_MODEL = "tcg-at-tpmModel"
      OID_TCG_AT_TPM_VERSION = "tcg-at-tpmVersion"
      OID_TCG_KP_AIK_CERTIFICATE = "Attestation Identity Key Certificate"
    else
      OID_TCG = "2.23.133"
      OID_TCG_AT_TPM_MANUFACTURER = "#{OID_TCG}.2.1"
      OID_TCG_AT_TPM_MODEL = "#{OID_TCG}.2.2"
      OID_TCG_AT_TPM_VERSION = "#{OID_TCG}.2.3"
      OID_TCG_KP_AIK_CERTIFICATE = "#{OID_TCG}.8.3"
    end

    def self.from_der(certificate_der)
      new(OpenSSL::X509::Certificate.new(certificate_der))
    end

    def conformant?
      in_use? &&
        valid_version? &&
        valid_extended_key_usage? &&
        valid_basic_constraints? &&
        empty_subject? &&
        valid_subject_alternative_name?
    end

    private

    def in_use?
      now = Time.now

      not_before < now && now < not_after
    end

    def valid_version?
      version == ASN_V3
    end

    def valid_basic_constraints?
      basic_constraints = extension("basicConstraints")

      basic_constraints && basic_constraints.value == "CA:FALSE" && basic_constraints.critical?
    end

    def valid_extended_key_usage?
      extended_key_usage = extension("extendedKeyUsage")

      extended_key_usage && extended_key_usage.value == OID_TCG_KP_AIK_CERTIFICATE && !extended_key_usage.critical?
    end

    def empty_subject?
      subject.eql?(EMPTY_NAME)
    end

    def valid_subject_alternative_name?
      if san_extension
        san_extension.critical? &&
          valid_tpm_manufacturer? &&
          valid_tpm_model? &&
          valid_tpm_version?
      end
    end

    def valid_tpm_manufacturer?
      TPM::VENDOR_IDS.key?(tpm_manufacturer)
    end

    def valid_tpm_model?
      tpm_model && !tpm_model.empty?
    end

    def valid_tpm_version?
      tpm_version && !tpm_version.empty?
    end

    def extension(oid)
      extensions.detect { |ext| ext.oid == oid }
    end

    def tpm_manufacturer
      san_attributes[OID_TCG_AT_TPM_MANUFACTURER]
    end

    def tpm_model
      san_attributes[OID_TCG_AT_TPM_MODEL]
    end

    def tpm_version
      san_attributes[OID_TCG_AT_TPM_VERSION]
    end

    def san_attributes
      @san_attributes ||= parse_san_attributes
    end

    def parse_san_attributes
      return {} unless san_extension

      san_asn1 =
        OpenSSL::ASN1.decode(san_extension).find do |val|
          val.tag_class == :UNIVERSAL && val.tag == OpenSSL::ASN1::OCTET_STRING
        end

      general_names = OpenSSL::ASN1.decode(san_asn1.value)
      return {} unless general_names.is_a?(OpenSSL::ASN1::Sequence)

      directory_name =
        general_names.find do |val|
          val.tag_class == :CONTEXT_SPECIFIC && val.tag == SAN_DIRECTORY_NAME &&
            val.value.is_a?(Array) && !val.value.empty?
        end
      return {} unless directory_name

      OpenSSL::X509::Name.new(directory_name.value.first).to_a.each_with_object({}) do |(oid, value, _type), attributes|
        attributes[oid] ||= value
      end
    rescue OpenSSL::OpenSSLError
      {}
    end

    def san_extension
      extension("subjectAltName")
    end
  end
end
