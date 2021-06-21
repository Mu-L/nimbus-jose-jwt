package com.nimbusds.jose;

/**
 * The JOSE identifiers to use when creating JWEs, JWKs, etc...
 *
 * @see <a href="https://www.iana.org/assignments/jose/jose.xhtml">JSON Object Signing and Encryption (JOSE)</a>
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public interface JOSEIdentifiers {


  ////////////////////////////////////////////////////////////////////////////////
  // RFC 7516 (JWE) Header Parameters
  ////////////////////////////////////////////////////////////////////////////////


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.1">RFC 7516 "alg" (Algorithm) Header Parameter</a>
   */
  String ALGORITHM = "alg";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.2">RFC 7516 "enc" (Encryption Algorithm) Header Parameter</a>
   */
  String ENCRYPTION_ALGORITHM = "enc";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.3">RFC 7516 "zip" (Compression Algorithm) Header Parameter</a>
   */
  String COMPRESSION_ALGORITHM = "zip";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.4">RFC 7516 "jku" (JWK Set URL) Header Parameter</a>
   */
  String JWK_SET_URL = "jku";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.5">RFC 7516 "jwk" (JSON Web Key) Header Parameter</a>
   */
  String JSON_WEB_KEY = "jwk";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.6">RFC 7516 "kid" (Key ID) Header Parameter</a>
   */
  String KEY_ID = "kid";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.7">RFC 7516 "x5u" (X.509 URL) Header Parameter</a>
   */
  String X_509_URL = "x5u";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.8">RFC 7516 "x5c" (X.509 Certificate Chain) Header Parameter</a>
   */
  String X_509_CERT_CHAIN = "x5c";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.9">RFC 7516 "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter</a>
   */
  String X_509_CERT_SHA_1_THUMBPRINT = "x5t";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.10">RFC 7516 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
   *         Parameter</a>
   */
  String X_509_CERT_SHA_256_THUMBPRINT = "x5t#S256";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.11">RFC 7516 "typ" (Type) Header Parameter</a>
   */
  String TYPE = "typ";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.12">RFC 7516 "cty" (Content Type) Header Parameter</a>
   */
  String CONTENT_TYPE = "cty";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-4.1.13">RFC 7516 "crit" (Critical) Header Parameter</a>
   */
  String CRITICAL = "crit";


  ////////////////////////////////////////////////////////////////////////////////
  // RFC 7518 (JWA) Header Parameters
  ////////////////////////////////////////////////////////////////////////////////


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.1">RFC 7518 "epk" (Ephemeral Public Key) Header Parameter</a>
   */
  String EPHEMERAL_PUBLIC_KEY = "epk";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.2">RFC 7518 "apu" (Agreement PartyUInfo) Header Parameter</a>
   */
  String AGREEMENT_PARTY_U_INFO = "apu";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.1.3">RFC 7518 "apv" (Agreement PartyVInfo) Header Parameter</a>
   */
  String AGREEMENT_PARTY_V_INFO = "apv";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.1">RFC 7518 "iv" (Initialization Vector) Header Parameter</a>
   */
  String INITIALIZATION_VECTOR = "iv";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.7.1.2">RFC 7518 "tag" (Authentication Tag) Header Parameter</a>
   */
  String AUTHENTICATION_TAG = "tag";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.1">RFC 7518 "p2s" (PBES2 Salt Input) Header Parameter</a>
   */
  String PBES2_SALT_INPUT = "p2s";


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-4.8.1.2">RFC 7518 "p2c" (PBES2 Count) Header Parameter</a>
   */
  String PBES2_COUNT = "p2c";


  ////////////////////////////////////////////////////////////////////////////////
  // RFC 7797 (JWS Unencoded Payload Option) Header Parameters
  ////////////////////////////////////////////////////////////////////////////////


  /**
   * @see <a href="https://datatracker.ietf.org/doc/html/rfc7797#section-3">RFC 7797 "b64" (base64url-encode payload) Header Parameter</a>
   */
  String BASE64_URL_ENCODE_PAYLOAD = "b64";
}
