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
```

Linux/macOS:
```bash
chmod +x build_native.sh
./build_native.sh
```

## Set secret key

Use environment variable:

```bash
export BYTECODE_KEY="YourSecureKeyHere"
```

or on Windows:

```bat
set BYTECODE_KEY=YourSecureKeyHere
```

## Compile Java

```bash
javac -d out src/com/seaboat/bytecode/*.java src/test/*.java
```

## Run sample test

```bash
java -cp out test.ByteCodeEncryptorTest
```

## Encrypt JAR

```bash
java -cp out test.JarEncryptorTest D:\jarpath\helloworld.jar
```

## Run encrypted app

```bash
java -agentlib:ByteCodeEncryptor -cp helloworld_encrypted.jar cn.zzp.HelloWorld
```
