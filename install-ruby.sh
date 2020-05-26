source ~/.rvm/scripts/rvm

if [[ "${LIBSSL}" == "1.0" ]]; then
  rvm install $RB --autolibs=read-only -C --with-openssl-dir=usr/include/openssl
elif [[ "${LIBSSL}" == "1.1" ]]; then
  rvm install $RB --binary --fuzzy
fi

rvm use $RB
ruby -ropenssl -e 'puts OpenSSL::OPENSSL_VERSION'
