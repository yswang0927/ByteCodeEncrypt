package com.seaboat.bytecode;

/**
 * Native bytecode encrypt/decrypt helper.
 */
public class ByteCodeEncryptor {
    static {
        System.loadLibrary("ByteCodeEncryptor");
    }

    /**
     * Default compatibility method.
     */
    public native static byte[] encrypt(byte[] input);

    /**
     * Default compatibility method.
     */
    public native static byte[] decrypt(byte[] input);

    /**
     * Recommended variant: bind encryption to the actual class name.
     */
    public static byte[] encrypt(byte[] input, String className) {
        return encryptInternal(input, className);
    }

    public static byte[] decrypt(byte[] input, String className) {
        return decryptInternal(input, className);
    }

    private static native byte[] encryptInternal(byte[] input, String className);

    private static native byte[] decryptInternal(byte[] input, String className);
}
