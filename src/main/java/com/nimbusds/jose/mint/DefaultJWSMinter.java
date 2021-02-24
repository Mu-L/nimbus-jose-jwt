package com.nimbusds.jose.mint;

import java.util.List;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
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

	/**
	 * Signs and serializes a new JWT using the provided {@link JWSHeader}
	 * and {@link JWTClaimsSet}.
	 *
	 * Derives the signing key from the {@link JWSHeader} as well as any
	 * application-specific {@link SecurityContext context}.
	 *
	 * If multiple keys are matched against the header's criteria, the
	 * first will be used to sign the JWT. To customize this, you can
	 * set a custom {@link JWKSource} like so:
	 *
	 * <code>
	 *  public static class MyJWKSource implements JWKSource&lt;SecurityContext&gt; {
	 *     private final JWKSource&lt;SecurityContext&gt; delegate;
	 *
	 *     public List&lt;JWK&gt; get(final JWKSelector jwkSelector, final SecurityContext context)
	 *         throws KeySourceException {
	 *         List&lt;JWK&gt; jwks = this.delegate.get(jwkSelector, context);
	 *         return jwks.get(jwks.size() - 1); // get last one instead
	 *     }
	 *  }
	 *
	 *  minter.setJWKSource(new MyJWKSource(jwkSource));
	 * </code>
	 *
	 * or you can select your own {@link JWK} and do:
	 *
	 * <code>
	 *  minter.setJWKSource(new JWKSecurityContextJWKSet());
	 *
	 *  // ...
	 *
	 *  JWK jwk = findJWK();
	 *  minter.mint(header, claims, new JWKSecurityContext(jwks));
	 * </code>
	 *
	 * Once the key is discovered, adds any headers related to the discovered
	 * signing key, including {@code kid}, {@code x5u}, {@code x5c}, and
	 * {@code x5t#256}.
	 *
	 * All other headers and claims remain as-is. This method
	 * expects the caller to add the {@code typ}, {@code alg},
	 * and any other needed headers.
	 *
	 * @param header the {@link JWSHeader} to use, less the {@code kid}, which
	 *               this method will derive
	 * @param payload the {@link Payload} to use
	 * @param context a {@link SecurityContext}
	 * @return a signed JWT
	 * @throws JOSEException if the instance is improperly configured,
	 * if no appropriate JWK can be found, or if signing fails
	 */
	@Override
	public JWSObject mint(JWSHeader header, Payload payload, C context) throws JOSEException {
		List<JWK> jwks = jwks(header, context);
		if (jwks.isEmpty()) {
			throw new JOSEException("No JWKs found for signing");
		}
		JWK jwk = jwks.get(0);
		JWSHeader withJwk = new JWSHeader.Builder(header)
				.keyID(jwk.getKeyID())
				.x509CertURL(jwk.getX509CertURL())
				.x509CertChain(jwk.getX509CertChain())
				.x509CertSHA256Thumbprint(jwk.getX509CertSHA256Thumbprint())
				.x509CertThumbprint(jwk.getX509CertThumbprint())
				.build();
		JWSObject jws = new JWSObject(withJwk, payload);
		if (this.jwsSignerFactory == null) {
			throw new JOSEException("No JWS signer factory configured");
		}
		jws.sign(this.jwsSignerFactory.createJWSSigner(jwk));
		return jws;
	}

	private List<JWK> jwks(JWSHeader header, C context) throws JOSEException {
		JWKMatcher matcher = JWKMatcher.forJWSHeader(header);
		JWKSelector selector = new JWKSelector(matcher);
		if (context instanceof JWKSecurityContext) {
			return selector.select(new JWKSet(((JWKSecurityContext) context).getKeys()));
		}
		if (this.jwkSource == null) {
			throw new JOSEException("No JWK source configured");
		}
		return this.jwkSource.get(selector, context);
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
