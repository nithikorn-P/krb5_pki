package org.krb5_pki;

import com.sun.security.auth.callback.TextCallbackHandler;
import org.ietf.jgss.*;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.*;
import java.security.Principal;
import java.security.PrivilegedAction;
import java.util.Base64;
import java.util.Set;

public final class KerberosTicketRetriever
{
    private final static Oid KERB_V5_OID;
    private final static Oid KRB5_PRINCIPAL_NAME_OID;

    static {
        try
        {
            KERB_V5_OID = new Oid("1.2.840.113554.1.2.2");
            KRB5_PRINCIPAL_NAME_OID = new Oid("1.2.840.113554.1.2.2.1");

        } catch (final GSSException ex)
        {
            throw new Error(ex);
        }
    }

    /**
     * Not to be instanciated
     */
    private KerberosTicketRetriever() {};

    /**
     *
     */
    private static class TicketCreatorAction implements PrivilegedAction
    {
        final String userPrincipal;
        final String applicationPrincipal;

        private StringBuffer outputBuffer;

        /**
         *
         * @param userPrincipal  p.ex. <tt>MuelleHA@MYFIRM.COM</tt>
         * @param applicationPrincipal  p.ex. <tt>HTTP/webserver.myfirm.com</tt>
         */
        private TicketCreatorAction(final String userPrincipal, final String applicationPrincipal)
        {
            this.userPrincipal = userPrincipal;
            this.applicationPrincipal = applicationPrincipal;
        }

        private void setOutputBuffer(final StringBuffer newOutputBuffer)
        {
            outputBuffer = newOutputBuffer;
        }

        /**
         * Only calls {@link #createTicket()}
         * @return <tt>null</tt>
         */
        public Object run()
        {
            try
            {
                createTicket();
            }
            catch (final GSSException  ex)
            {
                throw new Error(ex);
            }

            return null;
        }

        /**
         *
         * @throws GSSException
         */
        private void createTicket () throws GSSException
        {
            final GSSManager manager = GSSManager.getInstance();
            final GSSName clientName = manager.createName(userPrincipal, KRB5_PRINCIPAL_NAME_OID);
            final GSSCredential clientCred = manager.createCredential(clientName,
                    8 * 3600,
                    KERB_V5_OID,
                    GSSCredential.INITIATE_ONLY);

            final GSSName serverName = manager.createName(applicationPrincipal, KRB5_PRINCIPAL_NAME_OID);

            final GSSContext context = manager.createContext(serverName,
                    KERB_V5_OID,
                    clientCred,
                    GSSContext.DEFAULT_LIFETIME);
            context.requestMutualAuth(true);
            context.requestConf(false);
            context.requestInteg(true);

            final byte[] outToken = context.initSecContext(new byte[0], 0, 0);

            if (outputBuffer !=null)
            {
                outputBuffer.append(String.format("Src Name: %s\n", context.getSrcName()));
                outputBuffer.append(String.format("Target  : %s\n", context.getTargName()));
                outputBuffer.append(new String(Base64.getEncoder().encode(outToken)));
                outputBuffer.append("\n");
            }

            context.dispose();
        }
    }

    /**
     *
     * @param realm p.ex. <tt>MYFIRM.COM</tt>
     * @param kdc p.ex. <tt>kerbserver.myfirm.com</tt>
     * @param userPrincipal cf. user@EXAMPLE.COM
     * @param applicationPrincipal   cf. HOST/user.example.com
     * @throws GSSException
     * @throws LoginException
     */
    static public String retrieveTicket(
            final String realm,
            final String kdc,
            final String userPrincipal,
            final String applicationPrincipal)
            throws GSSException, LoginException
    {

        // create the jass-config-file
        final File jaasConfFile;
        try
        {
            jaasConfFile = File.createTempFile("jaas.conf", null);
            final PrintStream bos = new PrintStream(new FileOutputStream(jaasConfFile));
            bos.print(String.format(
                    "Krb5LoginContext { com.sun.security.auth.module.Krb5LoginModule required refreshKrb5Config=true useTicketCache=true debug=true keytab=\"src/main/resources/ad-server.HTTP.keytab\" ; };"
            ));
            bos.close();
            jaasConfFile.deleteOnExit();
        }
        catch (final IOException ex)
        {
            throw new IOError(ex);
        }

        // set the properties
        System.setProperty("java.security.krb5.realm", realm);
        System.setProperty("java.security.krb5.kdc", kdc);
        System.setProperty("java.security.auth.login.config",jaasConfFile.getAbsolutePath());

        // get the Subject(), i.e. the current user under Windows
        final Subject subject = new Subject();
        final LoginContext lc = new LoginContext("Krb5LoginContext", subject, new TextCallbackHandler());
        lc.login();

        // extract our principal
        final Set<Principal> principalSet = subject.getPrincipals();
        if (principalSet.size() != 1)
            throw new AssertionError("No or several principals: " + principalSet);
//        final Principal userPrincipal = principalSet.iterator().next();

        // now try to execute the SampleAction as the authenticated Subject
        // action.run() without doAsPrivileged leads to
        //   No valid credentials provided (Mechanism level: Failed to find any Kerberos tgt)
//        final TicketCreatorAction action = new TicketCreatorAction(userPrincipal.getName(), applicationPrincipal);
        final TicketCreatorAction action = new TicketCreatorAction(userPrincipal, applicationPrincipal);
        final StringBuffer outputBuffer = new StringBuffer();
        action.setOutputBuffer(outputBuffer);
        Subject.doAs(lc.getSubject(), action);

        return outputBuffer.toString();
    }

    public static void main (final String args[]) throws Throwable
    {
        final String ticket = retrieveTicket("PROJECT.COM", "10.8.0.2", "ad-server@PROJECT.COM","HTTP/ad-server.project.com");
        System.out.println(ticket);
    }
}
