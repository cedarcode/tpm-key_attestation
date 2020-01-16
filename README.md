# tpm-key_attestation

TPM Key Attestation utitlies

[![Gem](https://img.shields.io/gem/v/tpm-key_attestation.svg?style=flat-square)](https://rubygems.org/gems/tpm-key_attestation)
[![Travis](https://img.shields.io/travis/cedarcode/tpm-key_attestation.svg?style=flat-square)](https://travis-ci.org/cedarcode/tpm-key_attestation)

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
TPM::KeyAttestation.new(
  certify_info,
  signature,
  certified_object,
  signing_key,
  hash_function,
  quilifying_data
).valid?
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cedarcode/tpm-key_attestation.

