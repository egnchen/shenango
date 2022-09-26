#!/bin/bash
make clean &&
make -j32 &&
make -C shim/ clean &&
make -C shim -j32 &&
make -C playground/ clean &&
make -C playground/
