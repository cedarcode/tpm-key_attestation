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
      # `scheme` is a TPMT_ECC_SCHEME: a selector followed by a [scheme]details
      # union whose size depends on the selector (Table 187 / Table 172 / Table
      # 158). TPM_ALG_NULL has empty details; TPM_ALG_ECDSA's details are a
      # TPMS_SCHEME_HASH, i.e. one extra 2-byte hashAlg. Without reading it the
      # parser desyncs by 2 bytes for every non-NULL scheme.
      uint16 :scheme_hash_alg, onlyif: -> { scheme != TPM::ALG_NULL }
      uint16 :curve_id
      uint16 :kdf
    end
  end
end
