package test;

import com.seaboat.bytecode.JarEncryptor;

public class JarEncryptorTest {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: JarEncryptorTest <jar-file>");
            return;
        }

        JarEncryptor.encrypt(args[0]);
    }
}
