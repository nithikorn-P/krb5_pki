package org.krb5_pki.encapsulation;

import java.security.PublicKey;

public class Response extends Encapsulation {

    private String data;

    public Response() {
        super(null);
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }
}
