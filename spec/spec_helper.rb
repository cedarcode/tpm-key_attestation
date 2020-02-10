# frozen_string_literal: true

require "bundler/setup"
require "tpm/key_attestation"
require "byebug"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def create_rsa_key
  key_bits = 1024 # NOTE: Use 2048 or more in real life. This choice is just for fast test runs.

  OpenSSL::PKey::RSA.new(key_bits)
end
