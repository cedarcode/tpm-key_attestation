# frozen_string_literal: true

require "bindata"
require "tpm/constants"

module TPM
  class TPublic < BinData::Record
    # Section 12.2.3.6 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    class SEccParms < BinData::Record
      endian :big

      uint16 :symmetric
      uint16 :scheme
      uint16 :scheme_hash_alg, onlyif: -> { scheme != TPM::ALG_NULL }
      uint16 :curve_id
      uint16 :kdf
    end
  end
end
