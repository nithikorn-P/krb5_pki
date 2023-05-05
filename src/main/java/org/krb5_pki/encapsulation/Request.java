package org.krb5_pki.encapsulation;

import java.security.PublicKey;

public class Request extends Encapsulation {
    private String realm;
    private String kdc;
    private String username;
    private String servicePrincipal;
    private String password;

    public Request(PublicKey publicKey) {
        super(publicKey);
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getKdc() {
        return kdc;
    }

    public void setKdc(String kdc) {
        this.kdc = kdc;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getServicePrincipal() {
        return servicePrincipal;
    }

    public void setServicePrincipal(String servicePrincipal) {
        this.servicePrincipal = servicePrincipal;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
