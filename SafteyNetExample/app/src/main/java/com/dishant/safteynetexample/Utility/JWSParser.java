package com.dishant.safteynetexample.Utility;

import com.dishant.safteynetexample.model.AttestationStatement;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;

import org.apache.http.conn.ssl.X509HostnameVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

public class JWSParser {

    private X509HostnameVerifier verifier = new X509HostnameVerifier() {
        @Override
        public boolean verify(String host, SSLSession session) {
            return false;
        }

        @Override
        public void verify(String host, SSLSocket ssl) throws IOException {

        }

        @Override
        public void verify(String host, X509Certificate cert) throws SSLException {

        }

        @Override
        public void verify(String host, String[] cns, String[] subjectAlts) throws SSLException {

        }
    };


    public AttestationStatement parseAndVerify(String signedAttestationStatment) {
        // Parse JSON Web Signature format.
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AttestationStatement.class).parse(signedAttestationStatment);
            X509Certificate cert;
            try {
                cert = jws.verifySignature();
                if (cert == null) {
                    System.err.println("Failure: Signature verification failed.");
                    return null;
                }
            } catch (GeneralSecurityException e) {
                System.err.println(
                        "Failure: Error during cryptographic verification of the JWS signature.");
                return null;
            }
            // Verify the hostname of the certificate.
            if (!verifyHostname(cert)) {
                System.err.println("Failure: Certificate isn't issued for the hostname attest.android" +
                        ".com.");
                return null;
            }
        } catch (Exception e) {
            return null;
        }
        return (AttestationStatement) jws.getPayload();

    }

    /**
     * Verifies that the certificate matches the specified hostname.
     * Uses the {@link X509HostnameVerifier} from the Apache HttpClient library
     * to confirm that the hostname matches the certificate.
     *
     * @param leafCert
     * @return
     */
    private boolean verifyHostname(X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            verifier.verify("attest.android.com", leafCert);
            return true;
        } catch (SSLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }


}
