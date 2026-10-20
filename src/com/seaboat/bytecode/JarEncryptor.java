package com.seaboat.bytecode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

public class JarEncryptor {

    public static void encrypt(String fileName) {
        try {
            File srcFile = new File(fileName);
            if (!srcFile.exists()) {
                throw new IllegalArgumentException("Source JAR not found: " + fileName);
            }

            String base = fileName.substring(0, fileName.lastIndexOf('.'));
            File dstFile = new File(base + "_encrypted.jar");

            try (JarFile srcJar = new JarFile(srcFile);
                 FileOutputStream fos = new FileOutputStream(dstFile);
                 JarOutputStream dstJar = new JarOutputStream(fos)) {

                byte[] buf = new byte[8192];
                Enumeration<JarEntry> entries = srcJar.entries();

                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();

                    if (entry.isDirectory()) {
                        JarEntry copy = new JarEntry(entry.getName());
                        dstJar.putNextEntry(copy);
                        dstJar.closeEntry();
                        continue;
                    }

                    try (InputStream is = srcJar.getInputStream(entry)) {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream();
                        int len;
                        while ((len = is.read(buf)) != -1) {
                            baos.write(buf, 0, len);
                        }

                        byte[] bytes = baos.toByteArray();
                        String name = entry.getName();

                        if (name.endsWith(".class")) {
                            String className = name.replace('/', '.');
                            bytes = ByteCodeEncryptor.encryptInternal(bytes, className);
                        }

                        JarEntry outEntry = new JarEntry(name);
                        dstJar.putNextEntry(outEntry);
                        dstJar.write(bytes);
                        dstJar.closeEntry();
                    }
                }
            }

            System.out.println("Encrypt finished: " + dstFile.getAbsolutePath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
