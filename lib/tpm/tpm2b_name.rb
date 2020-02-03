# frozen_string_literal: true

require "bindata"
require "tpm/public_area"
require "tpm/tpmt_ha"

module TPM
  class Tpm2bName < BinData::Record
    endian :big

    uint16 :name_size, value: lambda { name.to_binary_s.size }
    tpmt_ha :name, read_length: :name_size

    def valid_for?(object)
      name.to_binary_s == TPM::PublicArea.new(object).name
    end
  end
end
