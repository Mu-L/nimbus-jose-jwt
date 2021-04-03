package com.nimbusds.jose.mint;

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;

/**
 * JSON Web Signature (JWS) minter configuration.
 *
 * <p>Specifies the required components to mint JWS objects:
 *
 * <ul>
 *     <li>JWK source to determine key candidate(s) for the JWS based on the
 *     JWS header and application-specific context information.
 *
 *     <li>Optional JWS signer factory. Creates the appropriate
 *     {@link com.nimbusds.jose.JWSSigner} for signing the object.
 * </ul>
 *
 * @author Josh Cummings
 * @version 2021-01-14
 */
public interface JWSMinterConfiguration<C extends SecurityContext> {
	
	/**
	 * Gets the source for looking up JWKs.
	 *
	 * @return The {@link JWKSource} in use.
	 */
	JWKSource<C> getJWKSource();

	
	/**
	 * Sets the source for to look up JWKs from.
	 *
	 * @param jwkSource The JWK source to use.
	 */
	void setJWKSource(final JWKSource<C> jwkSource);

	
	/**
	 * Gets the factory for generating {@link JWSSigner}s.
	 *
	 * @return The {@link JWSSignerFactory} in use.
	 */
	JWSSignerFactory getJWSSignerFactory();

	
	/**
	 * Sets the factory for generating {@link JWSSigner}s.
	 *
	 * @param jwsSignerFactory The JWS signer factory to use.
	 */
	void setJWSSignerFactory(final JWSSignerFactory jwsSignerFactory);
}
