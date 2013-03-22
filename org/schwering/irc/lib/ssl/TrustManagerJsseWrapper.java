/*
 * IRClib -- A Java Internet Relay Chat library -- class TrustManagerJsseWrapper
 * Copyright (C) 2002 - 2006 Christoph Schwering <schwering@gmail.com>
 * 
 * This library and the accompanying materials are made available under the
 * terms of the
 * 	- GNU Lesser General Public License,
 * 	- Apache License, Version 2.0 and
 * 	- Eclipse Public License v1.0.
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY.
 */

package org.schwering.irc.lib.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

/**
 * Wraps a <code>SSLTrustManager</code> in a <code>com.sun.net.ssl.X509TrustManager</code>.
 * 
 * @author Christoph Schwering &lt;schwering@gmail.com&gt;
 * @since 1.10
 * @version 1.00
 * @see SSLTrustManager
 * @see com.sun.net.ssl.TrustManager
 */
class TrustManagerJsseWrapper implements X509TrustManager {
    /**
     * The trust manager that is wrapped.
     */
    private SSLTrustManager trustManager;

    // ------------------------------

    public static TrustManagerJsseWrapper[] wrap(SSLTrustManager[] tm) {
        TrustManagerJsseWrapper[] w = new TrustManagerJsseWrapper[tm.length];
        for (int i = 0; i < tm.length; i++) {
            w[i] = new TrustManagerJsseWrapper(tm[i]);
        }
        return w;
    }

    // ------------------------------

    /**
     * Creates a new trust manager wrapper.
     * 
     * @param trustManager
     *            The <code>SSLTrustManager</code> that should be wrapped by a
     *            <code>com.sun.net.ssl.X509TrustManager</code>.
     */
    public TrustManagerJsseWrapper(SSLTrustManager trustManager) {
        if (trustManager == null) {
            throw new IllegalArgumentException("trustManager == null");
        }
        this.trustManager = trustManager;
    }

    // ------------------------------

    /**
     * Always throws <code>CertificateException</code>, as no clients are ever trusted.
     * 
     * @param chain
     *            The peer certificate chain.
     * @param authType
     *            The authentication type based on the client certificate.
     */
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException();
    }

    // ------------------------------

    /**
     * Throws <code>CertificateException</code> if the server is not trusted. This decision is made by the
     * <code>trustManager</code>.
     * 
     * @param chain
     *            The peer certificate chain.
     * @param authType
     *            The authentication type based on the server certificate.
     */
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (!trustManager.isTrusted(chain))
            throw new CertificateException();
    }

    // ------------------------------

    /**
     * Return an array of certificate authority certificates which are trusted for authenticating peers.
     * 
     * @return <code>trustManager.getAcceptedIssuers</code>.
     */
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }
}
