package org.krb5_pki;

import com.google.gson.Gson;
import org.krb5_pki.util.Algorithm;
import org.krb5_pki.util.EncryptUtil;
import org.krb5_pki.util.KeyUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Payload {
    private byte[] data;
    private byte[] key;

    public Payload(Object data, PublicKey publicKey) {
        Gson gson = new Gson();
        String jsonData = gson.toJson(data);
        SecretKey secretKey = KeyUtil.generateSecretKey();

        this.data = EncryptUtil.encrypt(Algorithm.AES, jsonData.getBytes(StandardCharsets.UTF_8), secretKey);
        this.key = EncryptUtil.encrypt(Algorithm.RSA, secretKey.getEncoded(), publicKey);
    }

    public String getJsonData(PrivateKey privateKey) {
        byte[] secretKeyByte = EncryptUtil.decrypt(Algorithm.RSA, this.key, privateKey);
        SecretKey secretKey = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, "AES");

        return EncryptUtil.decrypt(Algorithm.AES, this.data, secretKey).toString();
    }

    public <T> T getData(Class<T> tClass, PrivateKey privateKey) {
        Gson gson = new Gson();

        return gson.fromJson(getJsonData(privateKey), tClass);
    }

    public String toString() {
        Gson gson = new Gson();

        return gson.toJson(this);
    }
}
