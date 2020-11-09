#!/bin/bash

TARGET=${TARGET-x86_64-unknown-linux-gnu}
if [ "$TARGET" != "" ]; then
    TGT="--target $TARGET"
fi

cargo build

