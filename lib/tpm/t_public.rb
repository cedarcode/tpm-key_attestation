# frozen_string_literal: true

require "bindata"
require "openssl"
require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/t_public/s_ecc_parms"
require "tpm/t_public/s_rsa_parms"

module TPM
  # Section 12.2.4 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  class TPublic < BinData::Record
    BYTE_LENGTH = 8

    CURVE_TPM_TO_OPENSSL = {
      TPM::ECC_NIST_P256 => "prime256v1",
      TPM::ECC_NIST_P384 => "secp384r1",
      TPM::ECC_NIST_P521 => "secp521r1",
    }.freeze

    BN_BASE = 2
    RSA_KEY_DEFAULT_PUBLIC_EXPONENT = 2**16 + 1
    ECC_UNCOMPRESSED_POINT_INDICATOR = "\x04"

    class << self
      alias_method :deserialize, :read
    end

    endian :big

    uint16 :alg_type
    uint16 :name_alg

    # :object_attributes
    skip length: 4

    sized_buffer :auth_policy

    choice :parameters, selection: :alg_type do
      s_ecc_parms TPM::ALG_ECC
      s_rsa_parms TPM::ALG_RSA
    end

    choice :unique, selection: :alg_type do
      sized_buffer TPM::ALG_ECC
      sized_buffer TPM::ALG_RSA
    end

    def rsa?
      alg_type == TPM::ALG_RSA
    end

    def ecc?
      alg_type == TPM::ALG_ECC
    end

    def key
      if parameters.symmetric == TPM::ALG_NULL
        if ecc?
          ecc_key
        elsif rsa?
          rsa_key
        else
          raise "Type #{alg_type} not supported"
        end
      end
    end

    def openssl_curve_name
      if ecc?
        CURVE_TPM_TO_OPENSSL[parameters.curve_id] || raise("Unknown curve #{parameters.curve_id}")
      end
    end

    private

    def ecc_key
      if parameters.scheme == TPM::ALG_ECDSA
        group = OpenSSL::PKey::EC::Group.new(openssl_curve_name)
        point = OpenSSL::PKey::EC::Point.new(group, bn(ECC_UNCOMPRESSED_POINT_INDICATOR + unique.buffer.value))

        # RFC5480 SubjectPublicKeyInfo
        asn1 = OpenSSL::ASN1::Sequence(
          [
            OpenSSL::ASN1::Sequence(
              [
                OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                OpenSSL::ASN1::ObjectId(group.curve_name),
              ]
            ),
            OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
          ]
        )

        OpenSSL::PKey::EC.new(asn1.to_der)
      end
    end

    def rsa_key
      case parameters.scheme
      when TPM::ALG_RSASSA, TPM::ALG_RSAPSS, TPM::ALG_NULL
        n = unique.buffer.value

        if parameters.key_bits / BYTE_LENGTH == n.size
          # PKCS#1 RSAPublicKey
          asn1 = OpenSSL::ASN1::Sequence(
            [
              OpenSSL::ASN1::Integer.new(bn(n)),
              OpenSSL::ASN1::Integer.new(bn(RSA_KEY_DEFAULT_PUBLIC_EXPONENT)),
            ]
          )

          OpenSSL::PKey::RSA.new(asn1.to_der)
        end
      end
    end

    def bn(data)
      if data
        OpenSSL::BN.new(data, BN_BASE)
      end
    end
  end
end
