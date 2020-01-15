# frozen_string_literal: true

require "bindata"
require "openssl"
require "tpm/constants"
require "tpm/sized_buffer"
require "tpm/s_attest/s_certify_info"

module TPM
  # Section 10.12.8 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
  class SAttest < BinData::Record
    TPM_TO_OPENSSL_HASH_ALG = {
      ::TPM::ALG_SHA1 => "SHA1",
      ::TPM::ALG_SHA256 => "SHA256"
    }.freeze

    class << self
      alias_method :deserialize, :read
    end

    endian :big

    uint32 :magic
    uint16 :attested_type
    sized_buffer :qualified_signer
    sized_buffer :extra_data

    # s_clock_info :clock_info
    # uint64 :firmware_version
    skip length: 25

    choice :attested, selection: :attested_type do
      s_certify_info TPM::ST_ATTEST_CERTIFY
    end

    def valid?(attested_object, expected_extra_data)
      magic == TPM::GENERATED_VALUE &&
        valid_attested_object?(attested_object) &&
        extra_data.buffer == expected_extra_data
    end

    private

    def valid_attested_object?(attested_object)
      name_hash_alg = attested.name.buffer[0..1].unpack("n")[0]

      attested.name.buffer[2..-1] == OpenSSL::Digest.digest(TPM_TO_OPENSSL_HASH_ALG[name_hash_alg], attested_object)
    end
  end
end
