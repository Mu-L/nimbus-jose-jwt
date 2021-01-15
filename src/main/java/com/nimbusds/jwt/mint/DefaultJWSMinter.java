package com.nimbusds.jwt.mint;

import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Default minter of {@link com.nimbusds.jwt.SignedJWT signed}
 * JSON Web Tokens (JWTs).
 *
 * <p>Must be configured with the following:
 *
 * <ul>
 *     <li>A {@link #setJWKSource}  JWK key
 *     source} to select a JWK for signing.
 *     The key selection procedure is based on the {@link JWSHeader}
 *     by default, though may be customized by some
 *     {@link SecurityContext context}.</li>
 * </ul>
 *
 * <p>An optional {@link SecurityContext context} parameter is available to
 * facilitate passing of additional data between the caller and the underlying
 * selector of key candidates (in both directions).
 *
 * <p>See sections 6 of RFC 7515 (JWS) for guidelines on key selection.
 *
 * <p>This minter adds the "kid" header based on the JWK that it finds.
 *
 * @author Josh Cummings
 * @version 2021-01-14
 */
public class DefaultJWSMinter<C extends SecurityContext> implements ConfigurableJWSMinter<C> {
	private JWKSource<C> jwkSource;

	private JWSSignerFactory jwsSignerFactory = new DefaultJWSSignerFactory();

	@Override
	public String mint(JWSHeader header, JWTClaimsSet claims, C context) throws JOSEException {
		JWKMatcher matcher = JWKMatcher.forJWSHeader(header);
		JWKSelector selector = new JWKSelector(matcher);
		if (this.jwkSource == null) {
			throw new JOSEException("No JWK source configured");
		}
		List<JWK> jwks = this.jwkSource.get(selector, context);
		if (jwks.isEmpty()) {
			throw new JOSEException("No JWKs found for signing");
		}
		JWK jwk = jwks.get(0);
		JWSHeader withJwk = new JWSHeader.Builder(header)
				.keyID(jwk.getKeyID())
				.build();
		SignedJWT jwt = new SignedJWT(withJwk, claims);
		if (this.jwsSignerFactory == null) {
			throw new JOSEException("No JWS signer factory configured");
		}
		jwt.sign(this.jwsSignerFactory.createJWSSigner(jwk));
		return jwt.serialize();
	}

	@Override
	public JWKSource<C> getJWKSource() {
		return jwkSource;
	}

	@Override
	public void setJWKSource(JWKSource<C> jwkSource) {
		this.jwkSource = jwkSource;
	}

	@Override
	public JWSSignerFactory getJWSSignerFactory() {
		return jwsSignerFactory;
	}

	@Override
	public void setJWSSignerFactory(JWSSignerFactory jwsSignerFactory) {
		this.jwsSignerFactory = jwsSignerFactory;
	}
}
