package com.nimbusds.jwt;

import junit.framework.TestCase;

import static com.nimbusds.jwt.JWTClaimNames.*;

/**
 * Tests the correctness of the JWT Claim Name Constants.
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public class JWTClaimNamesTest extends TestCase {


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
