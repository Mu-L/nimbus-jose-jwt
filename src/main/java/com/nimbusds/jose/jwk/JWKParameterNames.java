package com.nimbusds.jose.jwk;


import com.nimbusds.jose.HeaderParameterNames;


/**
 * JSON Web Key (JWK) parameter names. The JWK parameter names defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a> (JWK),
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518</a> (JWA)
 * and other JOSE related standards are tracked in a
 * <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters">JWK
 * parameters registry</a> administered by IANA.
 *
 * @author Nathaniel Hart
 * @version 2021-07-02
 */
public interface JWKParameterNames {
	
	
	////////////////////////////////////////////////////////////////////////////////
	// Generic Key Parameters
	////////////////////////////////////////////////////////////////////////////////
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.1">RFC 7517 "kty" (Key Type) Parameter</a>
	 */
	String KEY_TYPE = "kty";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">RFC 7517 "use" (Public Key Use) Parameter</a>
	 */
	String PUBLIC_KEY_USE = "use";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">RFC 7517 "key_ops" (Key Operations) Parameter</a>
	 */
	String KEY_OPS = "key_ops";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.4">RFC 7517 "alg" (Algorithm) Parameter</a>
	 */
	String ALGORITHM = HeaderParameterNames.ALGORITHM;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">RFC 7517 "kid" (Key ID) Parameter</a>
	 */
	String KEY_ID = HeaderParameterNames.KEY_ID;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.6">RFC 7517 "x5u" (X.509 Certificate URL) Parameter</a>
	 */
	String X_509_CERT_URL = HeaderParameterNames.X_509_CERT_URL;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.7">RFC 7517 "x5c" (X.509 Certificate Chain) Parameter</a>
	 */
	String X_509_CERT_CHAIN = HeaderParameterNames.X_509_CERT_CHAIN;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.8">RFC 7517 "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter</a>
	 */
	String X_509_CERT_SHA_1_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.9">RFC 7517 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
	 * Parameter</a>
	 */
	String X_509_CERT_SHA_256_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT;
	
	
	////////////////////////////////////////////////////////////////////////////////
	// Algorithm-Specific Key Parameters
	////////////////////////////////////////////////////////////////////////////////
	
	
	// EC
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518 "crv" (EC Curve) Parameter</a>
	 */
	String ELLIPTIC_CURVE = "crv";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2">RFC 7518 "x" (EC X Coordinate) Parameter</a>
	 */
	String ELLIPTIC_CURVE_X_COORDINATE = "x";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3">RFC 7518 "y" (EC Y Coordinate) Parameter</a>
	 */
	String ELLIPTIC_CURVE_Y_COORDINATE = "y";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1">RFC 7518 "d" (EC Private Key) Parameter</a>
	 */
	String ELLIPTIC_CURVE_PRIVATE_KEY = "d";
	
	
	// RSA
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1">RFC 7518 "n" (RSA Modulus) Parameter</a>
	 */
	String RSA_MODULUS = "n";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2">RFC 7518 "e" (RSA Exponent) Parameter</a>
	 */
	String RSA_EXPONENT = "e";
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1">RFC 7518 "d" (RSA Private Exponent) Parameter</a>
	 */
	String RSA_PRIVATE_EXPONENT = ELLIPTIC_CURVE_PRIVATE_KEY;
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2">RFC 7518 "p" (RSA First Prime Factor) Parameter</a>
	 */
	String RSA_FIRST_PRIME_FACTOR = "p";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.3">RFC 7518 "q" (RSA Second Prime Factor) Parameter</a>
	 */
	String RSA_SECOND_PRIME_FACTOR = "q";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4">RFC 7518 "dp" (RSA First Factor CRT Exponent) Parameter</a>
	 */
	String RSA_FIRST_FACTOR_CRT_EXPONENT = "dp";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5">RFC 7518 "dq" (RSA Second Factor CRT Exponent) Parameter</a>
	 */
	String RSA_SECOND_FACTOR_CRT_EXPONENT = "dq";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6">RFC 7518 "qi" (RSA First CRT Coefficient) Parameter</a>
	 */
	String RSA_FIRST_CRT_COEFFICIENT = "qi";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7">RFC 7518 "oth" (RSA Other Primes Info) Parameter</a>
	 */
	String RSA_OTHER_PRIMES = "oth";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.1">RFC 7518 "r" (RSA Other Primes Info - Prime Factor)</a>
	 */
	String RSA_OTHER_PRIMES__PRIME_FACTOR = "r";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.2">RFC 7518 "d" (RSA Other Primes Info - Factor CRT Exponent)</a>
	 */
	String RSA_OTHER_PRIMES__FACTOR_CRT_EXPONENT = ELLIPTIC_CURVE_PRIVATE_KEY;
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.3">RFC 7518 "t" (RSA Other Primes Info - Factor CRT Coefficient)</a>
	 */
	String RSA_OTHER_PRIMES__FACTOR_CRT_COEFFICIENT = "t";
	
	
	// OCT
	
	
	/**
	 * Used with {@link KeyType#OCT}
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1">RFC 7518 "k" (OCT Key Value) Parameter</a>
	 */
	String OCT_KEY_VALUE = "k";
	
	
	// OKP
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "crv" (OKP Key Subtype) Parameter</a>
	 */
	String OKP_SUBTYPE = ELLIPTIC_CURVE;
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "x" (OKP Public Key) Parameter</a>
	 */
	String OKP_PUBLIC_KEY = ELLIPTIC_CURVE_X_COORDINATE;
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "d" (OKP Private Key) Parameter</a>
	 */
	String OKP_PRIVATE_KEY = ELLIPTIC_CURVE_PRIVATE_KEY;
}
