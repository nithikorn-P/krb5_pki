package org.krb5_pki;

import com.google.gson.Gson;
import org.krb5_pki.encapsulation.Request;
import org.krb5_pki.util.Algorithm;
import org.krb5_pki.util.EncryptUtil;
import org.krb5_pki.util.KeyUtil;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;

public class Client {

    private static void checkArguments(String[] args) {}

    public static void main(String[] args) throws Exception {
        checkArguments(args);

//        String principal    = args[0];
//        String password     = args[1];
        String kdc          = "http://10.8.0.2:4567";

        KeyPair clientKey = KeyUtil.generateKeyPair();
        KeyPair serverKey = KeyUtil.loadKeyPair("server");

        Request request = new Request(clientKey.getPublic());
        request.setServicePrincipal("HOST/ad-server.project.com");
        request.setPassword("TeePimPaper_30");

        Payload payload = new Payload(request, serverKey.getPublic());
        String  payloadString = payload.toString();

        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(new URI(kdc))
                .version(HttpClient.Version.HTTP_1_1)
                .POST(HttpRequest.BodyPublishers.ofString(payloadString))
                .build();

        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        System.out.println(response.statusCode());
        System.out.println(response.body());
    }
}
