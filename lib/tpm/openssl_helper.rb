# frozen_string_literal: true

module TPM
  module OpenSSLHelper
    def self.running_openssl_version_35_or_up?
      major, minor = OpenSSL::OPENSSL_LIBRARY_VERSION.match(/\d+\.\d+\.\d+/).to_s.split(".").map(&:to_i)

      major > 3 || (major == 3 && minor >= 5)
    end
  end
end
