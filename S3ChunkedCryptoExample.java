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

   public static void downloadAndDecrypt(AmazonS3 s3Client, String bucket, String key, File outputFile, SecretKey secretKey) throws Exception {
    try (S3Object s3Object = s3Client.getObject(bucket, key);
         InputStream s3is = s3Object.getObjectContent();
         FileOutputStream fos = new FileOutputStream(outputFile)) {

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        byte[] lenBytes = new byte[4];

        while (true) {
            if (!readFully(s3is, nonce)) break;
            if (!readFully(s3is, lenBytes)) throw new IOException("Unexpected end of stream (length)");

            int encryptedLength = bytesToInt(lenBytes);
            byte[] encryptedData = new byte[encryptedLength];

            if (!readFully(s3is, encryptedData)) throw new IOException("Unexpected end of stream (data)");

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce));
            byte[] decrypted = cipher.doFinal(encryptedData);

            fos.write(decrypted);
        }
    }
}

    public static void decryptRangeByChunkIndex(AmazonS3 s3Client, String bucket, String key,
                                            SecretKey secretKey, 
                                            int startChunk, int endChunk, File outputFile) throws Exception {
// Fetch metadata and extract chunkOffsets
    ObjectMetadata metadata = s3Client.getObjectMetadata(bucket, key);
    String encodedOffsets = metadata.getUserMetaDataOf("chunk-offsets");
    byte[] jsonBytes = Base64.getDecoder().decode(encodedOffsets);
    String json = new String(jsonBytes, "UTF-8");

    Map<Integer, Long> offsetMap = mapper.readValue(json, new TypeReference<Map<Integer, Long>>() {});
    List<Integer> sortedChunks = new ArrayList<>(offsetMap.keySet());
    Collections.sort(sortedChunks);

    try (FileOutputStream fos = new FileOutputStream(outputFile)) {
        for (int chunkIndex = startChunk; chunkIndex <= endChunk; chunkIndex++) {
            long start = chunkOffsets.get(chunkIndex);
            long end = (chunkIndex + 1 < chunkOffsets.size()) 
                        ? chunkOffsets.get(chunkIndex + 1) - 1
                        : null; // until end of file

            GetObjectRequest rangeRequest = new GetObjectRequest(bucket, key)
                    .withRange(start, end != null ? end : null);

            try (S3Object s3Object = s3Client.getObject(rangeRequest);
                 InputStream s3is = s3Object.getObjectContent()) {

                byte[] nonce = new byte[GCM_NONCE_LENGTH];
                byte[] lenBytes = new byte[4];

                if (!readFully(s3is, nonce)) throw new IOException("Missing nonce");
                if (!readFully(s3is, lenBytes)) throw new IOException("Missing length");

                int encLength = bytesToInt(lenBytes);
                byte[] encryptedData = new byte[encLength];

                if (!readFully(s3is, encryptedData)) throw new IOException("Missing encrypted data");

                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce));
                byte[] decrypted = cipher.doFinal(encryptedData);
                fos.write(decrypted);
            }
        }
    }
}
    private static boolean readFully(InputStream in, byte[] buffer) throws IOException {
    int offset = 0;
    int bytesRead;
    while (offset < buffer.length && (bytesRead = in.read(buffer, offset, buffer.length - offset)) != -1) {
        offset += bytesRead;
    }
    return offset == buffer.length;
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
