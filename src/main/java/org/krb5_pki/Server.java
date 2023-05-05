package org.krb5_pki;

import com.google.gson.Gson;
import org.ietf.jgss.GSSException;
import org.krb5_pki.encapsulation.Request;
import org.krb5_pki.encapsulation.Response;
import org.krb5_pki.util.KeyUtil;

import javax.security.auth.login.LoginException;
import java.security.KeyPair;
import java.util.Base64;

import static spark.Spark.*;

public class Server {
    private static String krb5Auth(Request request) throws GSSException, LoginException {
        return KerberosTicketRetriever.retrieveTicket(
                request.getRealm(),
                request.getKdc(),
                request.getUsername(),
                request.getServicePrincipal()
        );
    }

    private static String getTicket() {
        byte[] buffer = "ticket".getBytes();

        return Base64.getEncoder().encodeToString(buffer);
    }

    public static void main(String[] args) {
        KeyPair serverKeyPair;
        Gson    gson;

        serverKeyPair = KeyUtil.loadKeyPair("server");
        gson = new Gson();

        get("/", (request, response) -> "hello");

        post("/", (request, response) -> {
            Payload payloadIn = gson.fromJson(request.body(), Payload.class);
            Request clientRequest = payloadIn.getData(Request.class, serverKeyPair.getPrivate());

            //issue krb5 auth
            String ticket = krb5Auth(clientRequest);

            Response serverResponse = new Response();
            serverResponse.setData(ticket);

            Payload payloadOut = new Payload(serverResponse, clientRequest.getResponseKey());
            return payloadOut.toString();
        });
    }
}
