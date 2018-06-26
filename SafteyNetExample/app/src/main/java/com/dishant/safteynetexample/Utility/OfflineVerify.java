package com.dishant.safteynetexample.Utility;

/*
 * Copyright 2016 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import com.dishant.safteynetexample.model.AttestationStatement;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLException;

/**
 * Sample code to verify the device attestation statement offline.
 */
public class OfflineVerify {

    private static final DefaultHostnameVerifier HOSTNAME_VERIFIER = new DefaultHostnameVerifier();

    public static AttestationStatement parseAndVerify(String signedAttestationStatment) {
        // Parse JSON Web Signature format.
        JsonWebSignature jws;
        try {
            jws = JsonWebSignature.parser(JacksonFactory.getDefaultInstance())
                    .setPayloadClass(AttestationStatement.class).parse(signedAttestationStatment);
        } catch (IOException e) {
            System.err.println("Failure: " + signedAttestationStatment + " is not valid JWS " +
                    "format.");
            return null;
        }

        // Verify the signature of the JWS and retrieve the signature certificate.
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
        if (!verifyHostname("attest.android.com", cert)) {
            System.err.println("Failure: Certificate isn't issued for the hostname attest.android" +
                    ".com.");
            return null;
        }

        // Extract and use the payload data.
        AttestationStatement stmt = (AttestationStatement) jws.getPayload();
        return stmt;
    }

    /**
     * Verifies that the certificate matches the specified hostname.
     * Uses the {@link DefaultHostnameVerifier} from the Apache HttpClient library
     * to confirm that the hostname matches the certificate.
     *
     * @param hostname
     * @param leafCert
     * @return
     */
    private static boolean verifyHostname(String hostname, X509Certificate leafCert) {
        try {
            // Check that the hostname matches the certificate. This method throws an exception if
            // the cert could not be verified.
            HOSTNAME_VERIFIER.verify(hostname, leafCert);
            return true;
        } catch (SSLException e) {
            e.printStackTrace();
        }

        return false;
    }


}

