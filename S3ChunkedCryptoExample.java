package com.example.s3crypto;

import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.security.SecureRandom;
import java.util.*;

public class S3ChunkedCryptoExample {

    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int CHUNK_SIZE = 1024 * 1024;

    private static final ObjectMapper mapper = new ObjectMapper();
    private static final AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
            .withCredentials(new DefaultAWSCredentialsProviderChain())
            .withRegion("us-east-1")
            .build();

    public static void main(String[] args) throws Exception {
        File input = new File("input.txt");
        File tempEncrypted = new File("encrypted.dat");
        File tempDecrypted = new File("decrypted.txt");

        SecretKey key = generateKey();
        Map<Integer, Long> offsetMap = new LinkedHashMap<>();

        System.out.println("Encrypting file...");
        encryptInChunks(input, tempEncrypted, key, offsetMap);

        System.out.println("Uploading encrypted file with offset metadata...");
        uploadWithOffsetMetadata(tempEncrypted, offsetMap, "your-bucket", "encrypted/input.dat");

        System.out.println("Downloading and decrypting full file...");
        downloadAndDecrypt("your-bucket", "encrypted/input.dat", tempDecrypted, key);

        System.out.println("Downloading and decrypting partial file...");
        File rangeDecrypted = new File("partial_decrypted.txt");
        decryptRangeByChunkIndex("your-bucket", "encrypted/input.dat", key, 0, 0, rangeDecrypted);
    }

    private static void encryptInChunks(File inputFile, File outputFile, SecretKey key, Map<Integer, Long> offsetMap) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile);
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] buffer = new byte[CHUNK_SIZE];
            int bytesRead;
            int chunkIndex = 0;
            long currentOffset = 0;
            SecureRandom random = new SecureRandom();

            while ((bytesRead = fis.read(buffer)) != -1) {
                offsetMap.put(chunkIndex++, currentOffset);

                byte[] nonce = new byte[GCM_NONCE_LENGTH];
                random.nextBytes(nonce);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);

                byte[] encrypted = cipher.doFinal(Arrays.copyOf(buffer, bytesRead));

                fos.write(nonce);
                fos.write(intToBytes(encrypted.length));
                fos.write(encrypted);

                currentOffset += GCM_NONCE_LENGTH + 4 + encrypted.length;
            }
        }
    }

    private static void uploadWithOffsetMetadata(File encryptedFile, Map<Integer, Long> offsetMap, String bucket, String key) throws Exception {
        ObjectMetadata metadata = new ObjectMetadata();
        metadata.setContentLength(encryptedFile.length());

        String offsetsJson = mapper.writeValueAsString(offsetMap);
        metadata.addUserMetadata("chunk-offsets", Base64.getEncoder().encodeToString(offsetsJson.getBytes("UTF-8")));

        PutObjectRequest request = new PutObjectRequest(bucket, key, new FileInputStream(encryptedFile), metadata);
        s3Client.putObject(request);
    }

    private static void downloadAndDecrypt(String bucket, String key, File outputFile, SecretKey keySecret) throws Exception {
        S3Object s3Object = s3Client.getObject(bucket, key);
        ObjectMetadata metadata = s3Object.getObjectMetadata();
        String encodedOffsets = metadata.getUserMetaDataOf("chunk-offsets");

        byte[] jsonBytes = Base64.getDecoder().decode(encodedOffsets);
        String json = new String(jsonBytes, "UTF-8");

        Map<Integer, Long> offsetMap = mapper.readValue(json, new TypeReference<Map<Integer, Long>>() {});

        try (InputStream is = s3Object.getObjectContent();
             FileOutputStream fos = new FileOutputStream(outputFile)) {

            byte[] nonce = new byte[GCM_NONCE_LENGTH];
            byte[] lenBytes = new byte[4];

            while (is.read(nonce) != -1) {
                is.read(lenBytes);
                int len = bytesToInt(lenBytes);
                byte[] enc = new byte[len];
                is.read(enc);

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
                cipher.init(Cipher.DECRYPT_MODE, keySecret, spec);
                byte[] dec = cipher.doFinal(enc);

                fos.write(dec);
            }
        }
    }

    public static void decryptRangeByChunkIndex(String bucket, String key, SecretKey secretKey,
                                            int startChunkIndex, int endChunkIndex, File outputFile) throws Exception {
    // Fetch metadata and extract chunkOffsets
    ObjectMetadata metadata = s3Client.getObjectMetadata(bucket, key);
    String encodedOffsets = metadata.getUserMetaDataOf("chunk-offsets");
    byte[] jsonBytes = Base64.getDecoder().decode(encodedOffsets);
    String json = new String(jsonBytes, "UTF-8");

    Map<Integer, Long> offsetMap = mapper.readValue(json, new TypeReference<Map<Integer, Long>>() {});
    List<Integer> sortedChunks = new ArrayList<>(offsetMap.keySet());
    Collections.sort(sortedChunks);

    // Calculate byte range
    long startByte = offsetMap.get(startChunkIndex);
    long endByte = (endChunkIndex + 1 < sortedChunks.size())
            ? offsetMap.get(endChunkIndex + 1) - 1
            : metadata.getContentLength() - 1;

    System.out.println("Downloading bytes from " + startByte + " to " + endByte);

    GetObjectRequest rangeRequest = new GetObjectRequest(bucket, key)
            .withRange(startByte, endByte);

    S3Object s3Object = s3Client.getObject(rangeRequest);

    try (InputStream is = s3Object.getObjectContent();
         FileOutputStream fos = new FileOutputStream(outputFile)) {

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        byte[] lenBytes = new byte[4];

        while (is.read(nonce) != -1) {
            is.read(lenBytes);
            int len = bytesToInt(lenBytes);
            byte[] enc = new byte[len];
            is.read(enc);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            byte[] dec = cipher.doFinal(enc);
            fos.write(dec);
        }
    }
}


    private static SecretKey generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    private static byte[] intToBytes(int value) {
        return new byte[] {
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
