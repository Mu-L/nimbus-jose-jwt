package com.nimbusds.jwt;


/**
 * JSON Web Token (JWT) claim names. The claim names defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7519">RFC 7519</a> (JWT)
 * and other standards, such as OpenID Connect, are tracked in a
 * <a href="https://www.iana.org/assignments/jwt/jwt.xhtml#claims">JWT claims
 * registry</a> administered by IANA.
 *
 * @author Nathaniel Hart
 * @version 2021-06-15
 */
public interface JWTClaimNames {
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1">RFC 7519 "iss" (Issuer) Claim</a>
	 */
	String ISSUER = "iss";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2">RFC 7519 "sub" (Subject) Claim</a>
	 */
	String SUBJECT = "sub";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">RFC 7519 "aud" (Audience) Claim</a>
	 */
	String AUDIENCE = "aud";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4">RFC 7519 "exp" (Expiration Time) Claim</a>
	 */
	String EXPIRATION_TIME = "exp";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5">RFC 7519 "nbf" (Not Before) Claim</a>
	 */
	String NOT_BEFORE = "nbf";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6">RFC 7519 "iat" (Issued At) Claim</a>
	 */
	String ISSUED_AT = "iat";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7">RFC 7519 "jti" (JWT ID) Claim</a>
	 */
	String JWT_ID = "jti";
}
