# frozen_string_literal: true

require "tpm/constants"
require "tpm/public_area"
require "tpm/s_attest"

module TPM
  class CertifyValidator
    attr_reader :info, :signature, :nonce, :object, :algorithm

    def initialize(info, signature, nonce, object, algorithm: "RS256")
      @info = info
      @signature = signature
      @nonce = nonce
      @object = object
      @algorithm = algorithm
    end

    def valid?(signing_key)
      valid_info? && valid_signature?(signing_key)
    end

    private

    def valid_info?
      attest.attested_type == TPM::ST_ATTEST_CERTIFY &&
        attest.extra_data.buffer == nonce &&
        attest.magic == TPM::GENERATED_VALUE &&
        attest.attested.name.buffer == TPM::PublicArea.new(object).name
    end

    def valid_signature?(signing_key)
      if rsa_pss?
        signing_key.verify_pss(hash_function, signature, info, salt_length: :auto, mgf1_hash: hash_function)
      else
        signing_key.verify(hash_function, signature, info)
      end
    end

    def attest
      @attest ||= TPM::SAttest.deserialize(info)
    end

    def hash_function
      "SHA#{algorithm[2..-1]}"
    end

    def rsa_pss?
      algorithm.start_with?("PS")
    end
  end
end
