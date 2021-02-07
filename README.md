# tpm-key_attestation

TPM Key Attestation utitlies

[![Gem](https://img.shields.io/gem/v/tpm-key_attestation.svg?style=flat-square&color=informational)](https://rubygems.org/gems/tpm-key_attestation)
[![Actions Build](https://github.com/cedarcode/tpm-key_attestation/workflows/build/badge.svg)](https://github.com/cedarcode/tpm-key_attestation/actions)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-informational.svg?style=flat-square)](https://conventionalcommits.org)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'tpm-key_attestation'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install tpm-key_attestation

## Usage

```ruby
key_attestation =
  TPM::KeyAttestation.new(
    certify_info,
    signature,
    certified_object,
    signing_key,
    quilifying_data,
    signature_algorithm: TPM::ALG_RSAPSS # Supported values: TPM::ALG_RSAPSS, TPM::ALG_RSASSA, TPM::ALG_ECDSA (default TPM::ALG_RSASSA)
  )

if key_attestation.valid?
  key_attestation.key
end
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cedarcode/tpm-key_attestation.

