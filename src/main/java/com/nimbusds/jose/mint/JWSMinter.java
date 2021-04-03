package com.nimbusds.jose.mint;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Interface for minting {@link JWSObject JSON Web Signature (JWS) objects} and
 * {@link com.nimbusds.jwt.SignedJWT signed JSON Web Tokens} (JWTs).
 *
 * An optional context parameter is available to facilitate passing of
 * additional data between the caller and the underlying JWS minter (in
 * both directions).
 *
 * @author Josh Cummings
 * @version 2021-01-14
 */
public interface JWSMinter<C extends SecurityContext> {
	
	
	/**
	 * Creates a new JSON Web Signature (JWS) object using the provided
	 * {@link JWSHeader} and {@link Payload}. To create a signed JSON Web
	 * Token (JWT) use the {@link JWTClaimsSet#toPayload()} method to
	 * obtain a {@link Payload} representation of the JWT claims.
	 *
	 * Derives the signing key from the {@link JWSHeader} as well as any
	 * application-specific {@link SecurityContext context}.
	 *
	 * Once the key is discovered, adds any headers related to the
	 * discovered signing key, including {@code kid}, {@code x5u},
	 * {@code x5c}, and {@code x5t#256}.
	 *
	 * All other headers and claims remain as-is. This method expects the
	 * caller to add the {@code typ}, {@code alg}, and any other needed
	 * headers.
	 *
	 * @param header  The {@link JWSHeader} to use, less any
	 *                key-identifying headers, which this method will
	 *                derive.
	 * @param payload The {@link Payload}.
	 * @param context A {@link SecurityContext}, {@code null} if not
	 *                specified.
	 *
	 * @return The signed JWS object.
	 *
	 * @throws JOSEException If the instance is improperly configured, if
	 * no appropriate JWK could be found, or if signing failed.
	 */
	JWSObject mint(final JWSHeader header, final Payload payload, final C context)
		throws JOSEException;
}
