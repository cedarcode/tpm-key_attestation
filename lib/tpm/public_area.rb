# frozen_string_literal: true

require "openssl"
require "tpm/t_public"

module TPM
  TPM_TO_OPENSSL_HASH_ALG = {
    TPM::ALG_SHA1 => "SHA1",
    TPM::ALG_SHA256 => "SHA256"
  }.freeze

  class PublicArea
    attr_reader :object

    def initialize(object)
      @object = object
    end

    def name
      [name_alg].pack("n") + name_digest
    end

    def key
      t_public.key
    end

    def ecc?
      t_public.ecc?
    end

    def openssl_curve_name
      t_public.openssl_curve_name
    end

    private

    def name_digest
      OpenSSL::Digest.digest(TPM_TO_OPENSSL_HASH_ALG[name_alg], object)
    end

    def name_alg
      t_public.name_alg
    end

    def t_public
      @t_public ||= TPM::TPublic.deserialize(object)
    end
  end
end
