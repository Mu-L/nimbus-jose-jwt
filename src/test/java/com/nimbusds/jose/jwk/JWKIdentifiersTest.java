package com.nimbusds.jose.jwk;

import junit.framework.TestCase;

import static com.nimbusds.jose.jwk.JWKIdentifiers.*;

/**
 * Tests the correctness of the JWK Identifier Constants.
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public class JWKIdentifiersTest extends TestCase {


  public void testConstantValues() {
    assertEquals("kty", KEY_TYPE);
    assertEquals("key_ops", KEY_OPS);
    assertEquals("use", PUBLIC_KEY_USE);
    assertEquals("enc", ENCRYPTION_ALGORITHM);
    assertEquals("sig", SIGNATURE);
    assertEquals("key_ops", KEY_OPS);
    assertEquals("alg", ALGORITHM);
    assertEquals("kid", KEY_ID);
    assertEquals("x5u", X_509_URL);
    assertEquals("x5c", X_509_CERT_CHAIN);
    assertEquals("x5t", X_509_CERT_SHA_1_THUMBPRINT);
    assertEquals("x5t#S256", X_509_CERT_SHA_256_THUMBPRINT);

    assertEquals("keys", KEYS);

    assertEquals("EC", ELLIPTIC_CURVE_KEY_TYPE);
    assertEquals("RSA", RSA_KEY_TYPE);
    assertEquals("oct", OCTET_SEQUENCE_KEY_TYPE);

    assertEquals("crv", CURVE);
    assertEquals("x", X_COORD);
    assertEquals("y", Y_COORD);
    assertEquals("d", ECC_PRIVATE_KEY);

    assertEquals("n", MODULUS);
    assertEquals("e", EXPONENT);
    assertEquals("d", PRIVATE_EXPONENT);
    assertEquals("p", FIRST_PRIME_FACTOR);
    assertEquals("q", SECOND_PRIME_FACTOR);
    assertEquals("dp", FIRST_FACTOR_CRT_EXPONENT);
    assertEquals("dq", SECOND_FACTOR_CRT_EXPONENT);
    assertEquals("qi", FIRST_CRT_COEFFICIENT);
    assertEquals("oth", OTHER_PRIMES);

    assertEquals("r", PRIME_FACTOR);
    assertEquals("d", FACTOR_CRT_EXPONENT);
    assertEquals("t", FACTOR_CRT_COEFFICIENT);
    assertEquals("k", KEY_VALUE);

    assertEquals("OKP", OCTET_KEY_PAIR);
  }


}
