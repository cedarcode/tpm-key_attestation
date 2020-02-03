# frozen_string_literal: true

require "bindata"

module TPM
  class TpmtHa < BinData::Record
    BYTE_LENGTH = 8
    DIGEST_LENGTH_SHA1 = 160
    DIGEST_LENGTH_SHA256 = 256

    endian :big

    uint16 :hash_alg

    choice :digest, selection: :hash_alg do
      string TPM::ALG_SHA1, length: DIGEST_LENGTH_SHA1 / BYTE_LENGTH
      string TPM::ALG_SHA256, length: DIGEST_LENGTH_SHA256 / BYTE_LENGTH
    end
  end
end
