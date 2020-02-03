# frozen_string_literal: true

require "bindata"
require "tpm/sized_buffer"
require "tpm/tpm2b_name"

module TPM
  class SAttest < BinData::Record
    # Section 10.12.3 in https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
    class SCertifyInfo < BinData::Record
      tpm2b_name :name
      sized_buffer :qualified_name
    end
  end
end
