package com.nimbusds.jwt.mint;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Interface for minting and serializing {@link com.nimbusds.jwt.SignedJWT signed}
 * JSON Web Tokens (JWTs).
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
	 * Signs a new JWT using the provided {@link JWSHeader}
	 * and {@link JWTClaimsSet}.
	 *
	 * Derives the signing key from the {@link JWSHeader} as well as any
	 * application-specific {@link SecurityContext context}. Once discovered,
	 * adds any headers related to the discovered signing key, including
	 * {@code kid}, {@code x5u}, {@code x5c}, and {@code x5t#256}.
	 *
	 * All other headers and claims remain as-is. This method
	 * expects the caller to add the {@code typ}, {@code alg},
	 * and any other needed headers.
	 *
	 * @param header the {@link JWSHeader} to use, less the {@code kid}, which
	 *               this method will derive
	 * @param claims the {@link JWTClaimsSet} to use
	 * @param context a {@link SecurityContext} for communicating application-specific
	 * key information
	 * @return a signed JWT
	 * @throws JOSEException if the instance is improperly configured,
	 * if no appropriate JWK can be found, or if signing fails
	 */
	SignedJWT mint(JWSHeader header, JWTClaimsSet claims, C context) throws JOSEException;
}
