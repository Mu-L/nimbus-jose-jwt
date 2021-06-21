package com.nimbusds.jwt;

import junit.framework.TestCase;

import static com.nimbusds.jwt.JWTIdentifiers.*;

/**
 * Tests the correctness of the JWT Identifier Constants.
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public class JWTIdentifiersTest extends TestCase {


  public void testPayloadClaimValues() {
    assertEquals("iss", ISSUER);
    assertEquals("sub", SUBJECT);
    assertEquals("aud", AUDIENCE);
    assertEquals("exp", EXPIRATION_TIME);
    assertEquals("nbf", NOT_BEFORE);
    assertEquals("iat", ISSUED_AT);
    assertEquals("jti", JWT_ID);
  }
}
