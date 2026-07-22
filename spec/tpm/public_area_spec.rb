# frozen_string_literal: true

require "tpm/public_area"

RSpec.describe TPM::PublicArea do
  describe "#ecc?" do
    context "when the ECC scheme is TPM_ALG_NULL" do
      let(:pub_area) do
        [
          "0023000b0006047200000010001000030010002010" \
          "59fc716269b6410f6078517d86a532b9817dabb7719432c56d1ceb2d8bdc0500" \
          "2005be9216ff1185bcb2c97ba2e4f825ac8c4637876849312ee8c311b1ab126b0d"
        ].pack("H*")
      end

      it "returns true" do
        expect(described_class.new(pub_area).ecc?).to be true
      end
    end

    context "when the ECC scheme is TPM_ALG_ECDSA" do
      let(:pub_area) do
        [
          "0023000b0006047200000010001800" \
          "0b0003001000201059fc716269b6410f6078517d86a532b9817dabb7719432c" \
          "56d1ceb2d8bdc05002005be9216ff1185bcb2c97ba2e4f825ac8c4637876849312ee8c311b1ab126b0d"
        ].pack("H*")
      end

      it "returns true" do
        expect(described_class.new(pub_area).ecc?).to be true
      end
    end
  end
end
