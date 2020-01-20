# frozen_string_literal: true

require "tpm/key_attestation/version"
require "tpm/certify_validator"

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

    def key
      if valid?
        public_area.key
      end
    end

    def valid?
      TPM::CertifyValidator.new(
        certify_info,
        signature,
        qualifying_data,
        certified_object
      ).valid?(signing_key, hash_function)
    end

    private

    def public_area
      @public_area ||= TPM::PublicArea.new(certified_object)
    end
  end
end
