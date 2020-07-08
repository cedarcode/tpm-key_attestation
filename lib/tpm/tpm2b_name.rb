# frozen_string_literal: true

require "bindata"
require "tpm/tpmt_ha"

module TPM
  class Tpm2bName < BinData::Record
    endian :big

    uint16 :name_size, value: lambda { name.to_binary_s.size }
    tpmt_ha :name, read_length: :name_size

    def valid_for?(other_name)
      name.to_binary_s == other_name
    end
  end
end
