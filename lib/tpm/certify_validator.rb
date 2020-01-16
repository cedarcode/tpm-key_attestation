# frozen_string_literal: true

require "tpm/constants"
require "tpm/name"
require "tpm/s_attest"

module TPM
  class CertifyValidator
    attr_reader :info, :signature, :nonce, :object

    def initialize(info, signature, nonce, object)
      @info = info
      @signature = signature
      @nonce = nonce
      @object = object
    end

    def valid?(signing_key, hash_function)
      valid_info? && valid_signature?(signing_key, hash_function)
    end

    private

    def valid_info?
      attest.attested_type == TPM::ST_ATTEST_CERTIFY &&
        attest.extra_data.buffer == nonce &&
        attest.magic == TPM::GENERATED_VALUE &&
        TPM::Name.new(attest.attested.name.buffer).valid_for?(object)
    end

    def valid_signature?(signing_key, hash_function)
      signing_key.verify(hash_function, signature, info)
    end

    def attest
      @attest ||= TPM::SAttest.deserialize(info)
    end
  end
end
