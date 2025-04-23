package com.example.demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;

public class ChunkedFileCrypto {
    private static final int GCM_NONCE_LENGTH = 12; // 96 bits
    private static final int GCM_TAG_LENGTH = 16;  // 128 bits
    private static final int CHUNK_SIZE = 1024 * 1024; // 1MB

    public static void main(String[] args) throws Exception {
        File inputFile = new File("input.txt");
        File encryptedFile = new File("encrypted.dat");
        File decryptedFile = new File("decrypted.txt");
        File rangeDecryptedFile = new File("range_decrypted.txt");

        SecretKey key = generateKey();

        System.out.println("Encrypting...");
        encrypt(inputFile, encryptedFile, key);

        System.out.println("Decrypting...");
        decrypt(encryptedFile, decryptedFile, key);

        System.out.println("Decrypting byte range...");
        decryptByteRange(encryptedFile, rangeDecryptedFile, key, 0, CHUNK_SIZE); // First chunk
    }

    public static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static void encrypt(File inputFile, File outputFile, SecretKey key) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[CHUNK_SIZE];
            int bytesRead;
            SecureRandom random = new SecureRandom();

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] nonce = new byte[GCM_NONCE_LENGTH];
                random.nextBytes(nonce);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);

                byte[] encrypted = cipher.doFinal(Arrays.copyOf(buffer, bytesRead));

                fos.write(nonce);
                fos.write(intToBytes(encrypted.length));
                fos.write(encrypted);
            }
        }
    }

    public static void decrypt(File encryptedFile, File outputFile, SecretKey key) throws Exception {
        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            byte[] lenBytes = new byte[4];

            while (fis.read(nonce) != -1) {
                fis.read(lenBytes);
                int encLength = bytesToInt(lenBytes);
                byte[] encData = new byte[encLength];
                fis.read(encData);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
                byte[] decrypted = cipher.doFinal(encData);
                fos.write(decrypted);
            }
        }
    }

    public static void decryptByteRange(File encryptedFile, File outputFile, SecretKey key, int startByte, int endByte) throws Exception {
        try (FileInputStream fis = new FileInputStream(encryptedFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            byte[] lenBytes = new byte[4];
            int currentOffset = 0;

            while (fis.read(nonce) != -1) {
                fis.read(lenBytes);
                int encLength = bytesToInt(lenBytes);
                byte[] encData = new byte[encLength];
                fis.read(encData);

                int chunkTotalSize = GCM_NONCE_LENGTH + 4 + encLength;

                if (currentOffset + chunkTotalSize < startByte) {
                    currentOffset += chunkTotalSize;
                    continue;
                }

                if (currentOffset >= endByte) break;

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
                byte[] decrypted = cipher.doFinal(encData);
                fos.write(decrypted);

                currentOffset += chunkTotalSize;
            }
        }
    }

    private static byte[] intToBytes(int value) {
        return new byte[]{
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) value
        };
    }

    private static int bytesToInt(byte[] bytes) {
        return (bytes[0] & 0xFF) << 24 |
               (bytes[1] & 0xFF) << 16 |
               (bytes[2] & 0xFF) << 8 |
               (bytes[3] & 0xFF);
    }
}
