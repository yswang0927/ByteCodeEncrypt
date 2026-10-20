# ByteCodeEncrypt

A Java class bytecode protection demo powered by JNI + JVMTI + OpenSSL AES-GCM.

## Overview

This project demonstrates a practical pattern for protecting Java class files:
- encrypt `.class` files before packaging
- load a native JVMTI agent at JVM startup
- decrypt only selected package/class names during class loading
- validate integrity using AES-GCM tag checks
- cache decrypted classes for performance

This is not a silver bullet, but it is a production-oriented engineering pattern more realistic than simple char-by-char byte shifting.

## Requirements

- JDK 8 or above
- OpenSSL development headers/libs
- Windows or Linux/macOS toolchain
- Java runtime with access to native library path

## Build native library

Windows:

```bat
build_native.bat
