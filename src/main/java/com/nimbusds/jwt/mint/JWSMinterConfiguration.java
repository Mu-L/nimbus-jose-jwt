package com.nimbusds.jwt.mint;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;

/**
 * JWT minter configuration.
 *
 * <p>Specifies the required components to mint JWTs:
 *
 * <ul>
 *     <li>JWK source to determine key candidate(s) for JWS
 *     signing based on the JWS header and application-specific
 *     context information.
 *
 *     <li>Optional JWS signer factory. Creates the appropriate {@link com.nimbusds.jose.JWSSigner}
 *     for signing the JWT
 * </ul>
 *
 * @author Josh Cummings
 * @version 2021-01-14
 */
public interface JWSMinterConfiguration<C extends SecurityContext> {
	/**
	 * Gets the JWK source for looking up JWKs
	 *
	 * @return the {@link JWKSource} in use
	 */
	JWKSource<C> getJWKSource();

	/**
	 * Sets the source for to look up JWKs from
	 *
	 * @param jwkSource the JWK source to use
	 */
	void setJWKSource(JWKSource<C> jwkSource);

	/**
	 * Gets the JWS signer factory for generating {@link JWSSigner}s
	 *
	 * @return the {@link JWSSignerFactory} in use
	 */
	JWSSignerFactory getJWSSignerFactory();

	/**
	 * Sets the JWS signer factory to use
	 *
	 * @param jwsSignerFactory the JWS signer factory to use
	 */
	void setJWSSignerFactory(JWSSignerFactory jwsSignerFactory);
}
