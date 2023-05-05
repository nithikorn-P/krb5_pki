package org.krb5_pki.encapsulation;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

class Encapsulation {
    private final String responseKey;

    protected Encapsulation(PublicKey key) {
        byte[] keyBytes = key.getEncoded();
        responseKey = Base64.getEncoder().encodeToString(keyBytes);
    }

    public PublicKey getResponseKey() {
        KeyFactory  keyFactory;
        PublicKey   publicKey;

        try {
            keyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        byte[] publicKeyByte = Base64.getDecoder().decode(responseKey);
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(publicKeyByte);
        try {
            publicKey = keyFactory.generatePublic(encodedKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return publicKey;
    }
}
