# frozen_string_literal: true

require "tpm/key_attestation/version"
require "tpm/certify_validator"
require "tpm/constants"

module TPM
  class KeyAttestation
    class Error < StandardError; end

    attr_reader(
      :certify_info,
      :signature,
      :certified_key,
      :signing_key,
      :signature_algorithm,
      :hash_algorithm,
      :qualifying_data
    )

    def initialize(
      certify_info,
      signature,
      certified_key,
      signing_key,
      qualifying_data,
      signature_algorithm: ALG_RSASSA,
      hash_algorithm: ALG_SHA256
    )
      @certify_info = certify_info
      @signature = signature

      @certified_key = certified_key
      @signing_key = signing_key
      @signature_algorithm = signature_algorithm
      @hash_algorithm = hash_algorithm
      @qualifying_data = qualifying_data
    end

    def key
      if certify_validator.valid?(signing_key)
        public_area.key
      end
    end

    def valid?
      !!key
    end

    private

    def certify_validator
      @certify_validator ||=
        TPM::CertifyValidator.new(
          certify_info,
          signature,
          qualifying_data,
          certified_key,
          signature_algorithm: signature_algorithm,
          hash_algorithm: hash_algorithm
        )
    end

    def public_area
      @public_area ||= TPM::PublicArea.new(certified_key)
    end
  end
end
