package com.nimbusds.jose;

import com.nimbusds.jose.jwk.JWK;

/**
 * @author jricher
 *
 */
public class JWKException extends KeyException {

	public JWKException(String message) {
		super(message);
	}

	/**
	 * Creates a new key type exception.
	 *
	 * @param expectedKeyClass The expected key class. Should not be
	 *                         {@code null}.
	 */
	public static JWKException expectedClass(final Class<? extends JWK> expectedKeyClass) {
		return new JWKException("Invalid key: Must be an instance of " + expectedKeyClass);
	}


	public static JWKException expectedPrivate() {
		return new JWKException("Expected private key but none available.");
	}


}
