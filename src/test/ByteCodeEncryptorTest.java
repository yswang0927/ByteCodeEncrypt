package test;

import com.seaboat.bytecode.ByteCodeEncryptor;

public class ByteCodeEncryptorTest {
    public static void main(String[] args) {
        byte[] src = "hello-bytecode-protection".getBytes();

        byte[] encrypted = ByteCodeEncryptor.encrypt(src);
        byte[] decrypted = ByteCodeEncryptor.decrypt(encrypted);

        System.out.println("src len=" + src.length);
        System.out.println("enc len=" + encrypted.length);
        System.out.println("dec len=" + decrypted.length);

        System.out.println("decoded=" + new String(decrypted));
    }
}
