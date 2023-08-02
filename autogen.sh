#!/bin/sh
#

echo "creating configure -- autoreconf -sf"
autoreconf -i -s -f
echo "run ./configure [options] && make [options]"
