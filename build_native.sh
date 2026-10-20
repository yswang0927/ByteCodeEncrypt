#!/usr/bin/env bash
set -e

if [ -z "$JAVA_HOME" ]; then
  echo "JAVA_HOME is not set."
  exit 1
fi

g++ -shared -fPIC \
  -I"$JAVA_HOME/include" \
  -I"$JAVA_HOME/include/linux" \
  -I/usr/local/include \
  -o libByteCodeEncryptor.so \
  src/native/com_seaboat_bytecode_ByteCodeEncryptor.cpp \
  -lcrypto

echo "Build complete."
