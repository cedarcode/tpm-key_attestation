# frozen_string_literal: true

require "tpm/key_attestation/version"
require "tpm/certify_validator"

module TPM
  class KeyAttestation
    class Error < StandardError; end

    attr_reader :certify_info, :signature, :certified_object, :signing_key, :algorithm, :qualifying_data

    def initialize(certify_info, signature, certified_object, signing_key, qualifying_data, algorithm: "RS256")
      @certify_info = certify_info
      @signature = signature

      @certified_object = certified_object
      @signing_key = signing_key
      @algorithm = algorithm
      @qualifying_data = qualifying_data
    end

    def key
      if valid?
        public_area.key
      end
    end

    def valid?
      certify_validator.valid?(signing_key)
    end

    private

    def certify_validator
      @certify_validator ||=
        TPM::CertifyValidator.new(
          certify_info,
          signature,
          qualifying_data,
          certified_object,
          algorithm: algorithm
        )
    end

    def public_area
      @public_area ||= TPM::PublicArea.new(certified_object)
    end
  end
end
