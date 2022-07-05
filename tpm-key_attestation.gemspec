# frozen_string_literal: true

require_relative 'lib/tpm/key_attestation/version'

Gem::Specification.new do |spec|
  spec.name          = "tpm-key_attestation"
  spec.version       = TPM::KeyAttestation::VERSION
  spec.authors       = ["Gonzalo"]
  spec.license = "Apache-2.0"

  spec.summary       = "TPM Key Attestation verifier"
  spec.homepage      = "https://github.com/cedarcode/tpm-key_attestation"
  spec.required_ruby_version = Gem::Requirement.new(">= 2.4.0")

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "bindata", "~> 2.4"
  spec.add_dependency "openssl", "> 2.0", "< 3.1"
  spec.add_dependency "openssl-signature_algorithm", "~> 1.0"
end
