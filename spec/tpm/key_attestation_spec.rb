# frozen_string_literal: true

require "openssl"

RSpec.describe TPM::KeyAttestation do
  it "has a version number" do
    expect(TPM::KeyAttestation::VERSION).not_to be nil
  end

  let(:key_attestation) do
    TPM::KeyAttestation.new(
      certify_info,
      signature,
      certified_key,
      certificates,
      qualifying_data,
      signature_algorithm: signature_algorithm,
      hash_algorithm: hash_algorithm,
      trusted_certificates: trusted_certificates
    )
  end

  let(:certificates) { [certificate.to_der] }

  let(:certificate) do
    create_certificate(attestation_key, root_certificate, root_key)
  end

  let(:trusted_certificates) { [root_certificate] }

  let(:root_certificate) { create_root_certificate(root_key) }
  let(:root_key) { create_rsa_key }

  let(:certify_info) do
    s_attest = TPM::SAttest.new
    s_attest.magic = certify_info_magic
    s_attest.attested_type = TPM::ST_ATTEST_CERTIFY
    s_attest.extra_data.buffer = certify_info_extra_data
    s_attest.attested.name.name.hash_alg = name_alg
    s_attest.attested.name.name.digest = certify_info_attested_name_digest

    s_attest.to_binary_s
  end

  let(:signature_algorithm) { TPM::ALG_RSASSA }
  let(:hash_algorithm) { TPM::ALG_SHA256 }
  let(:signature) { attestation_key.sign(hash_function, to_be_signed) }

  let(:certify_info_magic) { TPM::GENERATED_VALUE }
  let(:certify_info_extra_data) { qualifying_data }
  let(:certify_info_attested_name_digest) { OpenSSL::Digest::SHA1.digest(certified_key) }
  let(:name_alg) { TPM::ALG_SHA1 }
  let(:to_be_signed) { certify_info }

  let(:attested_key) { create_rsa_key }
  let(:attested_key_length) { attested_key.n.num_bits }
  let(:certified_key) do
    t_public = TPM::TPublic.new
    t_public.alg_type = TPM::ALG_RSA
    t_public.name_alg = name_alg
    t_public.parameters.symmetric = TPM::ALG_NULL
    t_public.parameters.scheme = TPM::ALG_RSASSA
    t_public.parameters.key_bits = attested_key_length
    t_public.parameters.exponent = 0x00
    t_public.unique.buffer = attested_key.params["n"].to_s(2)

    t_public.to_binary_s
  end

  let(:hash_function) { "SHA256" }
  let(:qualifying_data) { OpenSSL::Digest::SHA256.digest("qualifying-data") }
  let(:attestation_key) { create_rsa_key }

  describe "#valid?" do
    context "when everything's in place" do
      it "returns true" do
        expect(key_attestation).to be_valid
      end
    end

    context "when using a certificate signed by default trusted certificates" do
      let(:trusted_certificates) { TPM::KeyAttestation::TRUSTED_CERTIFICATES.dup }

      TPM::KeyAttestation::TRUSTED_CERTIFICATES.reject do |certificate|
        certificate.subject == certificate.issuer
      end.dup.each do |intermediate_cert|
        context "when signed by intermediate certificate
          #{intermediate_cert.subject.to_s(OpenSSL::X509::Name::COMPAT)}" do
          let(:intermediate_certificate) do
            root_certificate = trusted_certificates.find do |trusted_certificate|
              trusted_certificate.subject == intermediate_cert.issuer
            end
            root_certificate.public_key = root_key
            root_certificate.sign(root_key, OpenSSL::Digest::SHA256.new)

            intermediate_cert.public_key = intermediate_key
            intermediate_cert.sign(root_key, OpenSSL::Digest::SHA256.new)

            intermediate_cert
          end

          let(:intermediate_key) { create_rsa_key }

          let(:certificate) do
            create_certificate(attestation_key, intermediate_certificate, intermediate_key)
          end

          it "returns true" do
            expect(key_attestation).to be_valid
          end
        end
      end

      TPM::KeyAttestation::TRUSTED_CERTIFICATES.select do |certificate|
        certificate.subject == certificate.issuer
      end.dup.each do |root_cert|
        context "when signed by root certificate
          #{root_cert.subject.to_s(OpenSSL::X509::Name::COMPAT)}" do
          let(:root_certificate) do
            root_cert.public_key = root_key
            root_cert.sign(root_key, OpenSSL::Digest::SHA256.new)

            root_cert
          end

          it "returns true" do
            with_duplicate_subject =
              TPM::KeyAttestation::TRUSTED_CERTIFICATES.any? do |c|
                c.serial != root_cert.serial && c.subject == root_cert.subject
              end

            if with_duplicate_subject
              skip "Re-instante once https://github.com/ruby/openssl/issues/389 is released"
            end

            expect(key_attestation).to be_valid
          end
        end
      end
    end

    context "when RSA PSS algorithm" do
      before do
        unless OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
          skip "Ruby OpenSSL gem #{OpenSSL::VERSION} do not support RSASSA-PSS"
        end
      end

      let(:signature_algorithm) { TPM::ALG_RSAPSS }
      let(:signature) do
        attestation_key.sign_pss(hash_function, to_be_signed, salt_length: :max, mgf1_hash: hash_function)
      end

      it "returns true" do
        expect(key_attestation).to be_valid
      end
    end

    context "when ECDSA algorithm" do
      let(:root_key) { create_ecc_key(curve_id) }
      let(:attestation_key) { create_ecc_key(curve_id) }
      let(:attested_key) { create_ecc_key(curve_id) }

      let(:signature_algorithm) { TPM::ALG_ECDSA }
      let(:hash_algorithm) { TPM::ALG_SHA256 }
      let(:hash_function) { "SHA256" }

      let(:certified_key) do
        t_public = TPM::TPublic.new
        t_public.alg_type = TPM::ALG_ECC
        t_public.name_alg = name_alg
        t_public.parameters.symmetric = TPM::ALG_NULL
        t_public.parameters.scheme = TPM::ALG_ECDSA
        t_public.parameters.curve_id = curve_id
        t_public.parameters.kdf = TPM::ALG_NULL
        t_public.unique.buffer = attested_key.public_key.to_bn.to_s(2)[1..-1]

        t_public.to_binary_s
      end

      let(:curve_id) { TPM::ECC_NIST_P256 }

      it "returns true" do
        expect(key_attestation).to be_valid

        expect(key_attestation.key).to be_a(OpenSSL::PKey::EC)
        expect(key_attestation.key.group.curve_name).to eq("prime256v1")
        expect(key_attestation.key.public_key).to eq(attested_key.public_key)
      end

      context "when P384 curve" do
        let(:hash_algorithm) { TPM::ALG_SHA384 }
        let(:hash_function) { "SHA384" }
        let(:curve_id) { TPM::ECC_NIST_P384 }

        it "returns true" do
          expect(key_attestation).to be_valid

          expect(key_attestation.key).to be_a(OpenSSL::PKey::EC)
          expect(key_attestation.key.group.curve_name).to eq("secp384r1")
          expect(key_attestation.key.public_key).to eq(attested_key.public_key)
        end
      end

      context "when P521 curve" do
        let(:hash_algorithm) { TPM::ALG_SHA512 }
        let(:hash_function) { "SHA512" }
        let(:curve_id) { TPM::ECC_NIST_P521 }

        it "returns true" do
          expect(key_attestation).to be_valid

          expect(key_attestation.key).to be_a(OpenSSL::PKey::EC)
          expect(key_attestation.key.group.curve_name).to eq("secp521r1")
          expect(key_attestation.key.public_key).to eq(attested_key.public_key)
        end
      end
    end

    context "when signature is invalid" do
      context "because is signed with a different hash function" do
        let(:signature) { attestation_key.sign("SHA1", to_be_signed) }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
      end

      context "because it was signed with an incorrect key" do
        let(:signature) { create_rsa_key.sign(hash_function, to_be_signed) }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
      end

      context "because it was signed over different data" do
        let(:to_be_signed) { "other data".b }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
      end

      context "because it is nonsense" do
        let(:signature) { "corrupted signature".b }

        it "returns false" do
          expect(key_attestation).not_to be_valid
        end
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
          let(:certify_info_attested_name_digest) do
            OpenSSL::Digest::SHA1.digest(certified_key + "X")
          end

          it "returns false" do
            expect(key_attestation).not_to be_valid
          end
        end

        context "because it was hashed with a different algorithm" do
          let(:certify_info_attested_name_digest) do
            OpenSSL::Digest::SHA256.digest(certified_key)
          end

          it "returns false" do
            expect(key_attestation).not_to be_valid
          end
        end
      end
    end
  end

  describe "#key" do
    context "when everything's in place" do
      it "returns a public RSA key with correct size" do
        expect(key_attestation.key.n.num_bits).to be 1024
      end

      it "returns a public RSA key with correct RSA modulus" do
        expect(key_attestation.key.n).to eq attested_key.n
      end

      it "returns a public RSA key with correct RSA exponent" do
        expect(key_attestation.key.e).to eq attested_key.e
      end
    end

    context "when RSA PSS algorithm" do
      before do
        unless OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
          skip "Ruby OpenSSL gem #{OpenSSL::VERSION} do not support RSASSA-PSS"
        end
      end

      let(:signature_algorithm) { TPM::ALG_RSAPSS }
      let(:signature) do
        attestation_key.sign_pss(hash_function, to_be_signed, salt_length: :max, mgf1_hash: hash_function)
      end

      it "returns a public RSA key with correct size" do
        expect(key_attestation.key.n.num_bits).to be 1024
      end

      it "returns a public RSA key with correct RSA modulus" do
        expect(key_attestation.key.n).to eq attested_key.n
      end

      it "returns a public RSA key with correct RSA exponent" do
        expect(key_attestation.key.e).to eq attested_key.e
      end
    end

    context "when is not valid" do
      before do
        expect(key_attestation).to receive(:valid?).and_return(false)
      end

      it 'returns nil' do
        expect(key_attestation.key).to be nil
      end
    end
  end
end
