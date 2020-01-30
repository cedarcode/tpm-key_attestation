# frozen_string_literal: true

require "openssl/signature_algorithm"
require "tpm/constants"
require "tpm/public_area"
require "tpm/s_attest"

module TPM
  class CertifyValidator
    attr_reader :info, :signature, :nonce, :object, :signature_algorithm, :hash_algorithm

    TPM_SIGNATURE_ALG_TO_OPENSSL = {
      ALG_RSASSA => OpenSSL::SignatureAlgorithm::RSAPKCS1,
      ALG_RSAPSS => OpenSSL::SignatureAlgorithm::RSAPSS,
      ALG_ECDSA => OpenSSL::SignatureAlgorithm::ECDSA
    }.freeze

    TPM_HASH_ALG_TO_OPENSSL = {
      ALG_SHA1 => "SHA1",
      ALG_SHA256 => "SHA256"
    }.freeze

    def initialize(info, signature, nonce, object, signature_algorithm: ALG_RSASSA, hash_algorithm: ALG_SHA256)
      @info = info
      @signature = signature
      @nonce = nonce
      @object = object
      @signature_algorithm = signature_algorithm
      @hash_algorithm = hash_algorithm
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

    def valid_signature?(verify_key)
      openssl_signature_algorithm = openssl_signature_algorithm_class.new(openssl_hash_function[3..-1])
      openssl_signature_algorithm.verify_key = verify_key

      begin
        openssl_signature_algorithm.verify(signature, info)
      rescue OpenSSL::SignatureAlgorithm::Error
        false
      end
    end

    def attest
      @attest ||= TPM::SAttest.deserialize(info)
    end

    def openssl_hash_function
      TPM_HASH_ALG_TO_OPENSSL[hash_algorithm] || raise("Unsupported hash algorithm #{hash_algorithm}")
    end

    def openssl_signature_algorithm_class
      TPM_SIGNATURE_ALG_TO_OPENSSL[signature_algorithm] || raise("Unsupported signature algorithm #{algorithm}")
    end
  end
end
