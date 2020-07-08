# frozen_string_literal: true

require "bindata"
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

    RSA_KEY_DEFAULT_PUBLIC_EXPONENT = 2**16 + 1

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

    def key
      if parameters.symmetric == TPM::ALG_NULL
        case alg_type
        when TPM::ALG_ECC
          ecc_key
        when TPM::ALG_RSA
          rsa_key
        else
          raise "Type #{alg_type} not supported"
        end
      end
    end

    private

    def ecc_key
      if parameters.scheme == TPM::ALG_ECDSA
        curve = CURVE_TPM_TO_OPENSSL[parameters.curve_id]

        if curve
          group = OpenSSL::PKey::EC::Group.new(curve)
          pkey = OpenSSL::PKey::EC.new(group)
          public_key_bn = OpenSSL::BN.new("\x04" + unique.buffer.value, 2)
          public_key_point = OpenSSL::PKey::EC::Point.new(group, public_key_bn)
          pkey.public_key = public_key_point

          pkey
        end
      end
    end

    def rsa_key
      case parameters.scheme
      when TPM::ALG_RSASSA, TPM::ALG_RSAPSS, TPM::ALG_NULL
        n = unique.buffer.value

        if parameters.key_bits / BYTE_LENGTH == n.size
          key = OpenSSL::PKey::RSA.new(parameters.key_bits.value)
          key.set_key(bn(n), bn(RSA_KEY_DEFAULT_PUBLIC_EXPONENT), nil)

          key.public_key
        end
      end
    end

    def bn(data)
      if data
        OpenSSL::BN.new(data, 2)
      end
    end
  end
end
