# frozen_string_literal: true

require "bindata"

module TPM
  class TpmsEccPoint < BinData::Record
    endian :big

    sized_buffer :x
    sized_buffer :y
  end
end
