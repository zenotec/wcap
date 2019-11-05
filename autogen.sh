#!/bin/bash

if [ "xxx$1xxx" == "xxx-ixxx" ] || [ "xxx$1xxx" == "xxx--installxxx" ]; then
  sudo apt-get update
  sudo apt-get install automake autoconf pkg-config libtool
  sudo apt-get install libnl-3-dev libnl-genl-3-dev libnl-route-3-dev
fi

mkdir -p ./build ./debug ./config ./m4
touch NEWS README AUTHORS ChangeLog
autoreconf --force --install -I config -I m4

