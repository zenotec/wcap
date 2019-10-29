#!/bin/sh

mkdir -p ./build ./debug ./config ./m4
touch NEWS README AUTHORS ChangeLog
autoreconf --force --install -I config -I m4

