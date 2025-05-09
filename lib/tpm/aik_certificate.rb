# frozen_string_literal: true

require "delegate"
require "openssl"
require "tpm/constants"

module TPM
  # Section 3.2 in https://www.trustedcomputinggroup.org/wp-content/uploads/Credential_Profile_EK_V2.0_R14_published.pdf
  class AIKCertificate < SimpleDelegator
    ASN_V3 = 2
    EMPTY_NAME = OpenSSL::X509::Name.new([]).freeze
    SAN_DIRECTORY_NAME = 4
    OID_TCG = "2.23.133"
    OID_TCG_AT_TPM_MANUFACTURER = "#{OID_TCG}.2.1"
    OID_TCG_AT_TPM_MODEL = "#{OID_TCG}.2.2"
    OID_TCG_AT_TPM_VERSION = "#{OID_TCG}.2.3"
    OID_TCG_KP_AIK_CERTIFICATE = "#{OID_TCG}.8.3"

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
          !tpm_manufacturer.empty? &&
          TPM::VENDOR_IDS[tpm_manufacturer] &&
          !tpm_model.empty? &&
          !tpm_version.empty?
      end
    end

    def extension(oid)
      extensions.detect { |ext| ext.oid == oid }
    end

    def tpm_manufacturer
      if san_name
        san_name.assoc(OID_TCG_AT_TPM_MANUFACTURER).at(1)
      end
    end

    def tpm_model
      if san_name
        san_name.assoc(OID_TCG_AT_TPM_MODEL).at(1)
      end
    end

    def tpm_version
      if san_name
        san_name.assoc(OID_TCG_AT_TPM_VERSION).at(1)
      end
    end

    def san_name
      if san_extension
        san_asn1 =
          OpenSSL::ASN1.decode(san_extension).find do |val|
            val.tag_class == :UNIVERSAL && val.tag == OpenSSL::ASN1::OCTET_STRING
          end

        directory_name =
          OpenSSL::ASN1.decode(san_asn1.value).find do |val|
            val.tag_class == :CONTEXT_SPECIFIC && val.tag == SAN_DIRECTORY_NAME
          end

        OpenSSL::X509::Name.new(directory_name.value.first).to_a
      end
    end

    def san_extension
      extension("subjectAltName")
    end
  end
end
