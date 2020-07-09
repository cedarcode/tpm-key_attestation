# frozen_string_literal: true

require "openssl/signature_algorithm"
require "tpm/constants"
require "tpm/s_attest"

module TPM
  class CertifyValidator
    attr_reader :info, :signature, :nonce, :public_area, :signature_algorithm, :hash_algorithm

    TPM_SIGNATURE_ALG_TO_OPENSSL = {
      ALG_RSASSA => OpenSSL::SignatureAlgorithm::RSAPKCS1,
      ALG_RSAPSS => OpenSSL::SignatureAlgorithm::RSAPSS,
      ALG_ECDSA => OpenSSL::SignatureAlgorithm::ECDSA
    }.freeze

    TPM_HASH_ALG_TO_OPENSSL = {
      ALG_SHA1 => "SHA1",
      ALG_SHA256 => "SHA256",
      ALG_SHA384 => "SHA384",
      ALG_SHA512 => "SHA512"
    }.freeze

    def initialize(info, signature, nonce, public_area, signature_algorithm: ALG_RSASSA, hash_algorithm: ALG_SHA256)
      @info = info
      @signature = signature
      @nonce = nonce
      @public_area = public_area
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
        attest.attested.name.valid_for?(public_area.name)
    end

    def valid_signature?(verify_key)
      openssl_signature_algorithm = openssl_signature_algorithm_class.new(**openssl_signature_algorithm_parameters)
      openssl_signature_algorithm.verify_key = verify_key
      openssl_signature_algorithm.verify(signature, info)
    rescue OpenSSL::SignatureAlgorithm::Error
      false
    end

    def attest
      @attest ||= TPM::SAttest.deserialize(info)
    end

    def openssl_signature_algorithm_parameters
      parameters = { hash_function: openssl_hash_function }

      if public_area.ecc?
        parameters[:curve] = public_area.openssl_curve_name
      end

      parameters
    end

    def openssl_hash_function
      TPM_HASH_ALG_TO_OPENSSL[hash_algorithm] || raise("Unsupported hash algorithm #{hash_algorithm}")
    end

    def openssl_signature_algorithm_class
      TPM_SIGNATURE_ALG_TO_OPENSSL[signature_algorithm] ||
        raise("Unsupported signature algorithm #{signature_algorithm}")
    end
  end
end
