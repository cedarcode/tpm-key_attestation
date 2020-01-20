# frozen_string_literal: true

require "openssl"

RSpec.describe TPM::KeyAttestation do
  it "has a version number" do
    expect(TPM::KeyAttestation::VERSION).not_to be nil
  end

  describe "#valid?" do
    context "when everything's in place" do
      let(:key_attestation) do
        TPM::KeyAttestation.new(
          certify_info,
          signature,
          attested_object,
          attestation_key,
          hash_function,
          qualifying_data
        )
      end

      let(:certify_info) do
        s_attest = TPM::SAttest.new
        s_attest.magic = TPM::GENERATED_VALUE
        s_attest.attested_type = TPM::ST_ATTEST_CERTIFY
        s_attest.extra_data.buffer = qualifying_data
        s_attest.attested.name.buffer = [name_alg].pack("n") + OpenSSL::Digest::SHA1.digest(attested_object)

        s_attest.to_binary_s
      end

      let(:signature) do
        attestation_key.sign(hash_function, certify_info)
      end

      let(:name_alg) { TPM::ALG_SHA1 }

      let(:attested_object) do
        t_public = TPM::TPublic.new
        t_public.alg_type = TPM::ALG_RSA
        t_public.name_alg = name_alg

        t_public.to_binary_s
      end

      let(:hash_function) { "SHA256" }
      let(:qualifying_data) { OpenSSL::Digest::SHA256.digest("qualyfing-data") }
      let(:attestation_key) { OpenSSL::PKey::RSA.new(2048) }

      it "returns true" do
        expect(key_attestation).to be_valid
      end
    end
  end
end
