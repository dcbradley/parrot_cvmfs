#!/bin/sh

echo "$@" | grep "enable-libcurl-builtin=no" > /dev/null
if [ $? -eq 0 ]; then
  exit 0
fi
echo "$@" | grep "enable-libcurl-builtin" > /dev/null
if [ $? -ne 0 ]; then
  exit 0
fi

./configure ${1+"$@"} LDFLAGS="$LDFLAGS -rdynamic" CFLAGS="$CFLAGS -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing -fasynchronous-unwind-tables -fno-omit-frame-pointer -fno-optimize-sibling-calls" && make 

