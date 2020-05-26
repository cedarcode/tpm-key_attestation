if [[ "${LIBSSL}" == "1.0" ]]; then
  sudo apt purge libssl-dev && sudo apt-get -yq --no-install-suggests --no-install-recommends install libssl1.0-dev
fi
