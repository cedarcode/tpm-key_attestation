# frozen_string_literal: true

require "openssl"

module TPM
  class Name
    TPM_TO_OPENSSL_HASH_ALG = {
      TPM::ALG_SHA1 => "SHA1",
      TPM::ALG_SHA256 => "SHA256"
    }.freeze

    attr_reader :name

    def initialize(name)
      @name = name
    end

    def valid_for?(object)
      name[2..-1] == OpenSSL::Digest.digest(hash_function, object)
    end

    private

    def hash_function
      TPM_TO_OPENSSL_HASH_ALG[hash_alg]
    end

    def hash_alg
      name[0..1].unpack("n")[0]
    end
  end
end
