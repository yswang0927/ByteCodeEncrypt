package com.seaboat.bytecode;

public class ByteCodeEncryptor {
    static {
        System.loadLibrary("ByteCodeEncryptor");
    }

    public native static byte[] encrypt(byte[] input);

    public native static byte[] decrypt(byte[] input);

    public static byte[] encrypt(byte[] input, String className) {
        return encryptInternal(input, className);
    }

    public static byte[] decrypt(byte[] input, String className) {
        return decryptInternal(input, className);
    }

    private static native byte[] encryptInternal(byte[] input, String className);

    private static native byte[] decryptInternal(byte[] input, String className);
}
