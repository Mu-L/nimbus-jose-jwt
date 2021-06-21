package com.nimbusds.jose;

import junit.framework.TestCase;

import static com.nimbusds.jose.JOSEIdentifiers.*;

/**
 * Tests the correctness of the JOSE Identifier Constants.
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public class JOSEIdentifiersTest extends TestCase {


  public void testConstantValues() {
    assertEquals("alg", ALGORITHM);
    assertEquals("enc", ENCRYPTION_ALGORITHM);
    assertEquals("zip", COMPRESSION_ALGORITHM);
    assertEquals("jku", JWK_SET_URL);
    assertEquals("jwk", JSON_WEB_KEY);
    assertEquals("kid", KEY_ID);
    assertEquals("typ", TYPE);
    assertEquals("x5u", X_509_URL);
    assertEquals("x5c", X_509_CERT_CHAIN);
    assertEquals("x5t", X_509_CERT_SHA_1_THUMBPRINT);
    assertEquals("x5t#S256", X_509_CERT_SHA_256_THUMBPRINT);
    assertEquals("typ", TYPE);
    assertEquals("cty", CONTENT_TYPE);
    assertEquals("crit", CRITICAL);

    assertEquals("epk", EPHEMERAL_PUBLIC_KEY);
    assertEquals("apu", AGREEMENT_PARTY_U_INFO);
    assertEquals("apv", AGREEMENT_PARTY_V_INFO);
    assertEquals("iv", INITIALIZATION_VECTOR);
    assertEquals("tag", AUTHENTICATION_TAG);
    assertEquals("p2s", PBES2_SALT_INPUT);
    assertEquals("p2c", PBES2_COUNT);

    assertEquals("b64", BASE64_URL_ENCODE_PAYLOAD);
  }
}
