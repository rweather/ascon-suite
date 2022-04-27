#!/bin/bash
#
# Helper script to build and test nearly all of the library configurations,
# so as to find broken combinations before they are pushed to the repository.

function build_config()
{
    rm -rf build
    mkdir build
    cd build
    echo "CONFIGURING: $*"
    cmake $* ..
    if test "$?" != "0" ; then
        echo "FAILED: cmake $*"
        exit 1
    fi
    echo "BUILDING: $*"
    make
    if test "$?" != "0" ; then
        echo "FAILED: build $*"
        exit 1
    fi
    echo "TESTING: $*"
    make test
    if test "$?" != "0" ; then
        echo "FAILED: test $*"
        exit 1
    fi
    echo "SUCCESS: $*"
    cd ..
    rm -rf build
}

build_config
build_config -DCHECK_ACQUIRE_RELEASE=ON

build_config -DBACKEND_C32=ON
build_config -DBACKEND_C32=ON -DCHECK_ACQUIRE_RELEASE=ON

build_config -DBACKEND_C64=ON
build_config -DBACKEND_C64=ON -DCHECK_ACQUIRE_RELEASE=ON

build_config -DBACKEND_DIRECT_XOR=ON
build_config -DBACKEND_DIRECT_XOR=ON -DCHECK_ACQUIRE_RELEASE=ON

build_config -DBACKEND_GENERIC=ON
build_config -DBACKEND_GENERIC=ON -DCHECK_ACQUIRE_RELEASE=ON

build_config -DKEY_SHARES=4 -DDATA_SHARES=4
build_config -DKEY_SHARES=4 -DDATA_SHARES=4 -DBACKEND_C32=ON
build_config -DKEY_SHARES=4 -DDATA_SHARES=4 -DBACKEND_C64=ON

build_config -DKEY_SHARES=4 -DDATA_SHARES=3
build_config -DKEY_SHARES=4 -DDATA_SHARES=3 -DBACKEND_C32=ON
build_config -DKEY_SHARES=4 -DDATA_SHARES=3 -DBACKEND_C64=ON

build_config -DKEY_SHARES=4 -DDATA_SHARES=2
build_config -DKEY_SHARES=4 -DDATA_SHARES=2 -DBACKEND_C32=ON
build_config -DKEY_SHARES=4 -DDATA_SHARES=2 -DBACKEND_C64=ON

build_config -DKEY_SHARES=4 -DDATA_SHARES=1
build_config -DKEY_SHARES=4 -DDATA_SHARES=1 -DBACKEND_C32=ON
build_config -DKEY_SHARES=4 -DDATA_SHARES=1 -DBACKEND_C64=ON

build_config -DKEY_SHARES=3 -DDATA_SHARES=3
build_config -DKEY_SHARES=3 -DDATA_SHARES=3 -DBACKEND_C32=ON
build_config -DKEY_SHARES=3 -DDATA_SHARES=3 -DBACKEND_C64=ON

build_config -DKEY_SHARES=3 -DDATA_SHARES=2
build_config -DKEY_SHARES=3 -DDATA_SHARES=2 -DBACKEND_C32=ON
build_config -DKEY_SHARES=3 -DDATA_SHARES=2 -DBACKEND_C64=ON

build_config -DKEY_SHARES=3 -DDATA_SHARES=1
build_config -DKEY_SHARES=3 -DDATA_SHARES=1 -DBACKEND_C32=ON
build_config -DKEY_SHARES=3 -DDATA_SHARES=1 -DBACKEND_C64=ON

build_config -DKEY_SHARES=2 -DDATA_SHARES=2
build_config -DKEY_SHARES=2 -DDATA_SHARES=2 -DBACKEND_C32=ON
build_config -DKEY_SHARES=2 -DDATA_SHARES=2 -DBACKEND_C64=ON

build_config -DKEY_SHARES=2 -DDATA_SHARES=1
build_config -DKEY_SHARES=2 -DDATA_SHARES=1 -DBACKEND_C32=ON
build_config -DKEY_SHARES=2 -DDATA_SHARES=1 -DBACKEND_C64=ON

exit 0
