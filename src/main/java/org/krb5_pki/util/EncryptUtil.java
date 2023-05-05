package org.krb5_pki.util;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class EncryptUtil {
    private EncryptUtil() {}

    public static byte[] encrypt(Algorithm algorithm, byte[] textByte, Key key) {
        Cipher cipher;
        byte[] cipherByte;

        try {
            cipher = Cipher.getInstance(algorithm.name());
            cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try {
            cipherByte = cipher.doFinal(textByte);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return cipherByte;
    }

    public static byte[] decrypt(Algorithm algorithm, byte[] cipherByte, Key key) {
        Cipher cipher;
        byte[] textByte;

        try {
            cipher = Cipher.getInstance(algorithm.name());
            cipher.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }

        try {
            textByte = cipher.doFinal(cipherByte);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return textByte;
    }
}
