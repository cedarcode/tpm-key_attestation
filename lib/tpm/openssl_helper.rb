# frozen_string_literal: true

module TPM
  module OpenSSLHelper
    def self.running_openssl_version_35_or_up?
      OpenSSL::OPENSSL_LIBRARY_VERSION.match(/\d+\.\d+\.\d+/).to_s >= "3.5.0"
    end
  end
end
