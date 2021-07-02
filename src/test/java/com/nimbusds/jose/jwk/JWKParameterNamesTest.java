package com.nimbusds.jose.jwk;


import static com.nimbusds.jose.jwk.JWKParameterNames.*;

import junit.framework.TestCase;


/**
 * Tests the correctness of the JWK Parameter Constants.
 *
 * @author Nathaniel Hart
 * @version 2021-07-02
 */
public class JWKParameterNamesTest extends TestCase {
	
	
	public void testConstantValues() {
		
		assertEquals("kty", KEY_TYPE);
		assertEquals("use", PUBLIC_KEY_USE);
		assertEquals("key_ops", KEY_OPS);
		assertEquals("alg", ALGORITHM);
		assertEquals("kid", KEY_ID);
		assertEquals("x5u", X_509_CERT_URL);
		assertEquals("x5c", X_509_CERT_CHAIN);
		assertEquals("x5t", X_509_CERT_SHA_1_THUMBPRINT);
		assertEquals("x5t#S256", X_509_CERT_SHA_256_THUMBPRINT);
		
		assertEquals("crv", ELLIPTIC_CURVE);
		assertEquals("x", ELLIPTIC_CURVE_X_COORDINATE);
		assertEquals("y", ELLIPTIC_CURVE_Y_COORDINATE);
		assertEquals("d", ELLIPTIC_CURVE_PRIVATE_KEY);
		
		assertEquals("n", RSA_MODULUS);
		assertEquals("e", RSA_EXPONENT);
		assertEquals("d", RSA_PRIVATE_EXPONENT);
		assertEquals("p", RSA_FIRST_PRIME_FACTOR);
		assertEquals("q", RSA_SECOND_PRIME_FACTOR);
		assertEquals("dp", RSA_FIRST_FACTOR_CRT_EXPONENT);
		assertEquals("dq", RSA_SECOND_FACTOR_CRT_EXPONENT);
		assertEquals("qi", RSA_FIRST_CRT_COEFFICIENT);
		assertEquals("oth", RSA_OTHER_PRIMES);
		assertEquals("r", RSA_OTHER_PRIMES__PRIME_FACTOR);
		assertEquals("d", RSA_OTHER_PRIMES__FACTOR_CRT_EXPONENT);
		assertEquals("t", RSA_OTHER_PRIMES__FACTOR_CRT_COEFFICIENT);
		
		assertEquals("k", OCT_KEY_VALUE);
		
		assertEquals("crv", OKP_SUBTYPE);
		assertEquals("x", OKP_PUBLIC_KEY);
		assertEquals("d", OKP_PRIVATE_KEY);
	}
}
