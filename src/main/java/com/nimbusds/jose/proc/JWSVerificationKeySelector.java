/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.proc;


import java.security.Key;
import java.security.PublicKey;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import javax.crypto.SecretKey;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyConverter;
import com.nimbusds.jose.jwk.source.JWKSource;


/**
 * Key selector for verifying JWS objects, where the key candidates are
 * retrieved from a {@link JWKSource JSON Web Key (JWK) source}.
 *
 * @author Vladimir Dzhuvinov
 * @author Marco Vermeulen
 * @version 2020-06-02
 */
@ThreadSafe
public class JWSVerificationKeySelector<C extends SecurityContext> extends AbstractJWKSelectorWithSource<C> implements JWSKeySelector<C> {


	/**
	 * The allowed JWS algorithms.
	 */
	private final Set<JWSAlgorithm> jwsAlgs;

	/**
	 * Present to maintain backward compatibility
	 */
	private final boolean singleJwsAlgConstructorWasCalled;

	/**
	 * Creates a new JWS verification key selector.
	 *
	 * @param jwsAlg    The allowed JWS algorithm for the objects to be
	 *                  verified. Must not be {@code null}.
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public JWSVerificationKeySelector(final JWSAlgorithm jwsAlg, final JWKSource<C> jwkSource) {
		super(jwkSource);
		if (jwsAlg == null) {
			throw new IllegalArgumentException("The JWS algorithm must not be null");
		}
		this.jwsAlgs = Collections.singleton(jwsAlg);
		this.singleJwsAlgConstructorWasCalled = true;
	}

	
	/**
	 * Creates a new JWS verification key selector.
	 *
	 * @param jwsAlgs   The allowed JWS algorithms for the objects to be
	 *                  verified. Must not be empty or {@code null}.
	 * @param jwkSource The JWK source. Must not be {@code null}.
	 */
	public JWSVerificationKeySelector(final Set<JWSAlgorithm> jwsAlgs, final JWKSource<C> jwkSource) {
		super(jwkSource);
		if (jwsAlgs == null || jwsAlgs.isEmpty()) {
			throw new IllegalArgumentException("The JWS algorithms must not be null or empty");
		}
		this.jwsAlgs = Collections.unmodifiableSet(jwsAlgs);
		this.singleJwsAlgConstructorWasCalled = false;
	}

	
	/**
	 * Checks if a JWS algorithm is allowed for key selection.
	 *
	 * @param jwsAlg The JWS algorithm to check.
	 *
	 * @return {@code true} if allowed, else {@code false}.
	 */
	public boolean isAllowed(final JWSAlgorithm jwsAlg) {
		return jwsAlgs.contains(jwsAlg);
	}


	/**
	 * Returns the expected JWS algorithm.
	 *
	 * @return The expected JWS algorithm.
	 * @deprecated Use {@link #isAllowed(JWSAlgorithm)} instead
	 */
	@Deprecated
	public JWSAlgorithm getExpectedJWSAlgorithm() {
		if (singleJwsAlgConstructorWasCalled) {
			return jwsAlgs.iterator().next();
		}
		throw new UnsupportedOperationException("Since this class was constructed with multiple " +
				"algorithms, the behavior of this method is undefined.");
	}

	/**
	 * Creates a JWK matcher for the expected JWS algorithm and the
	 * specified JWS header.
	 *
	 * @param jwsHeader The JWS header. Must not be {@code null}.
	 *
	 * @return The JWK matcher, {@code null} if none could be created.
	 */
	protected JWKMatcher createJWKMatcher(final JWSHeader jwsHeader) {

		if (! isAllowed(jwsHeader.getAlgorithm())) {
			// Unexpected JWS alg
			return null;
		} else {
			return JWKMatcher.forJWSHeader(jwsHeader);
		}
	}


	@Override
	public List<Key> selectJWSKeys(final JWSHeader jwsHeader, final C context)
		throws KeySourceException {

		if (! jwsAlgs.contains(jwsHeader.getAlgorithm())) {
			// Unexpected JWS alg
			return Collections.emptyList();
		}

		JWKMatcher jwkMatcher = createJWKMatcher(jwsHeader);
		if (jwkMatcher == null) {
			return Collections.emptyList();
		}

		List<JWK> jwkMatches = getJWKSource().get(new JWKSelector(jwkMatcher), context);

		List<Key> sanitizedKeyList = new LinkedList<>();

		for (Key key: KeyConverter.toJavaKeys(jwkMatches)) {
			if (key instanceof PublicKey || key instanceof SecretKey) {
				sanitizedKeyList.add(key);
			} // skip asymmetric private keys
		}

		return sanitizedKeyList;
	}
}
