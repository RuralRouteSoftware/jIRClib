package com.rrs_apps.java.jirclib.ssl;

import java.security.cert.X509Certificate;

/**
 * The default <code>TrustManager</code> of the <code>SSLIRCConnection</code>.
 * <p>
 * It automatically accepts the X509 certificate.
 * <p>
 * In many cases you should change the <code>SSLIRCConnection</code>'s <code>SSLTrustManager</code>. For examle if you
 * write an IRC client for human users, you may want to ask the user whether he accepts the server's certificate or not.
 * 
 * @author Christoph Schwering &lt;schwering@gmail.com&gt;
 * @since 1.10
 * @version 2.00
 * @see SSLIRCConnection
 * @see SSLTrustManager
 */
public class SSLDefaultTrustManager implements SSLTrustManager {

    /**
     * The <code>X509Certificate</code>s which are accepted.
     */
    protected X509Certificate[] accepted = new X509Certificate[0];

    // ------------------------------

    /**
     * Trusts the complete certificate chain and returns <code>true</code>.
     * 
     * @param chain
     *            The peer certificate chain.
     * @return <code>true</code>.
     */
    public boolean isTrusted(X509Certificate[] chain) {
        accepted = chain;
        return true;
    }

    // ------------------------------

    /**
     * Returns the accepted certificates. They are set in the <code>checkServerTrusted</code> method.
     * 
     * @return A non-null (possibly empty) array of acceptable CA issuer certificates.
     */
    public X509Certificate[] getAcceptedIssuers() {
        return accepted;
    }
}
