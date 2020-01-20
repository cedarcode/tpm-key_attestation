# frozen_string_literal: true

require "openssl"

RSpec.describe TPM::KeyAttestation do
  it "has a version number" do
    expect(TPM::KeyAttestation::VERSION).not_to be nil
  end

  describe "#valid?" do
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
      s_attest.magic = certify_info_magic
      s_attest.attested_type = TPM::ST_ATTEST_CERTIFY
      s_attest.extra_data.buffer = certify_info_extra_data
      s_attest.attested.name.buffer = certify_info_attested_name

      s_attest.to_binary_s
    end

    let(:signature) do
      attestation_key.sign(hash_function, certify_info)
    end

    let(:certify_info_magic) { TPM::GENERATED_VALUE }
    let(:certify_info_extra_data) { qualifying_data }
    let(:certify_info_attested_name) { [name_alg].pack("n") + OpenSSL::Digest::SHA1.digest(attested_object) }
    let(:name_alg) { TPM::ALG_SHA1 }

    let(:attested_object) do
      t_public = TPM::TPublic.new
      t_public.alg_type = TPM::ALG_RSA
      t_public.name_alg = name_alg

      t_public.to_binary_s
    end

    let(:hash_function) { "SHA256" }
    let(:qualifying_data) { OpenSSL::Digest::SHA256.digest("qualifying-data") }
    let(:attestation_key) { OpenSSL::PKey::RSA.new(2048) }

    context "when everything's in place" do
      it "returns true" do
        expect(key_attestation).to be_valid
      end
    end

    context "when certify info is invalid" do
      context "because magic is not TPM_GENERATED_VALUE" do
        let(:certify_info_magic) { TPM::GENERATED_VALUE + 1 }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
      end

      context "because extraData is not using the correct algorithm" do
        let(:certify_info_extra_data) { OpenSSL::Digest::SHA1.digest("qualifying-data") }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
      end

      context "because attested name is not a valid name for attested object" do
        context "because it was hashed on different data" do
          let(:certify_info_attested_name) do
            [TPM::ALG_SHA1].pack("n") + OpenSSL::Digest::SHA1.digest(attested_object + "X")
          end

          it "returns false" do
            expect(key_attestation).not_to be_valid
          end
        end

        context "because it was hashed with a different algorithm" do
          let(:certify_info_attested_name) do
            [TPM::ALG_SHA1].pack("n") + OpenSSL::Digest::SHA256.digest(attested_object)
          end

          it "returns false" do
            expect(key_attestation).not_to be_valid
          end
        end
      end
    end
  end
end
