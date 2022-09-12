#!/bin/bash
# rebuild the whole thing
make clean && make -j16 && \
cd shim && make clean && make -j16 && \
cd memcached && make clean && make -j16 && \
cd ../..
