package org.krb5_pki.util;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtil {
    private KeyUtil() {}

    private static String DIR_PATH = "key";

    public static SecretKey generateSecretKey() {
        KeyGenerator keyGenerator;

        try {
            keyGenerator = KeyGenerator.getInstance(Algorithm.AES.name());
            keyGenerator.init(128);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return keyGenerator.generateKey();
    }

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyGenerator;

        try {
            keyGenerator = KeyPairGenerator.getInstance(Algorithm.RSA.name());
            keyGenerator.initialize(2048);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return keyGenerator.generateKeyPair();
    }

    private static byte[] loadKey(String path) throws IOException {
        File            file;
        FileInputStream fileInputStream;
        byte[]          key;

        file = new File(path);
        fileInputStream = new FileInputStream(path);
        key = new byte[(int) file.length()];
        fileInputStream.read(key);
        fileInputStream.close();

        return key;
    }

    private static void saveKey(byte[] encodedKey, String path) throws IOException {
        FileOutputStream fileOutputStream;

        fileOutputStream = new FileOutputStream(path);
        fileOutputStream.write(encodedKey);
        fileOutputStream.close();
    }

    public static KeyPair loadKeyPair(String name) {
        String      path = String.format("%s/%s", DIR_PATH, name);
        byte[]      privateKeyByte;
        byte[]      publicKeyByte;
        PrivateKey  privateKey;
        PublicKey   publicKey;

        try {
            privateKeyByte = loadKey(path + "/private.key");
            publicKeyByte = loadKey(path + "/public.key");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance(Algorithm.RSA.name());

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyByte);
            publicKey = keyFactory.generatePublic(publicKeySpec);

            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyByte);
            privateKey = keyFactory.generatePrivate(privateKeySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return new KeyPair(publicKey, privateKey);
    }

    public static void saveKeyPair(String name, KeyPair keyPair) throws IOException {
        String      path;
        PrivateKey  privateKey;
        PublicKey   publicKey;

        path = String.format("%s/%s", DIR_PATH, name);
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        new File(path).mkdirs();

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
        saveKey(pkcs8EncodedKeySpec.getEncoded(), path + "/private.key");

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
        saveKey(x509EncodedKeySpec.getEncoded(), path + "/public.key");
    }

}
