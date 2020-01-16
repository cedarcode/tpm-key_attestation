# frozen_string_literal: true

require "tpm/key_attestation/version"

module TPM
  class KeyAttestation
    class Error < StandardError; end

    attr_reader :certify_info, :signature, :certified_object, :signing_key, :hash_function, :qualifying_data

    def initialize(certify_info, signature, certified_object, signing_key, hash_function, qualifying_data)
      @certify_info = certify_info
      @signature = signature

      @certified_object = certified_object
      @signing_key = signing_key
      @hash_function = hash_function
      @qualifying_data = qualifying_data
    end

    def valid?
      valid_signature? && valid_certify_info?
    end

    private

    def valid_signature?
      signing_key.verify(hash_function, signature, certify_info)
    end

    def valid_certify_info?
      s_attest.valid?(certified_object, qualifying_data)
    end

    def s_attest
      @s_attest ||= ::TPM::SAttest.read(certify_info)
    end
  end
end
