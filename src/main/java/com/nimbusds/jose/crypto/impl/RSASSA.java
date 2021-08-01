/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.impl;


import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;


/**
 * RSA-SSA functions and utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-02-20
 */
public class RSASSA {


	/**
	 * Returns a signer and verifier for the specified RSASSA-based JSON
	 * Web Algorithm (JWA).
	 *
	 * @param alg The JSON Web Algorithm (JWA). Must be supported and not
	 *            {@code null}.
	 *
	 * @return A signer and verifier instance.
	 *
	 * @throws JOSEException If the algorithm is not supported.
	 */
	public static Signature getSignerAndVerifier(final JWSAlgorithm alg,
						     final Provider provider)
		throws JOSEException {

		Signature signature = null;

		if (alg.equals(JWSAlgorithm.RS256)
				&& (signature = getSignerAndVerifier("SHA256withRSA", provider)) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.RS384)
				&& (signature = getSignerAndVerifier("SHA384withRSA", provider)) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.RS512)
				&& (signature = getSignerAndVerifier("SHA512withRSA", provider)) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS256) // JWA mandates salt length equals hash
				&& (signature = getSignerAndVerifier("RSASSA-PSS", provider, new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1))) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS256)
				&& (signature = getSignerAndVerifier("SHA256withRSAandMGF1", provider)) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS384) // JWA mandates salt length equals hash
				&& (signature = getSignerAndVerifier("RSASSA-PSS", provider, new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1))) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS384)
				&& (signature = getSignerAndVerifier("SHA384withRSAandMGF1", provider)) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS512) // JWA mandates salt length equals hash
				&& (signature = getSignerAndVerifier("RSASSA-PSS", provider, new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1))) != null) {

			return signature;

		} else if (alg.equals(JWSAlgorithm.PS512)
				&& (signature = getSignerAndVerifier("SHA512withRSAandMGF1", provider)) != null) {

			return signature;

		}

		throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, RSASSAProvider.SUPPORTED_ALGORITHMS));
	}

	private static Signature getSignerAndVerifier(final String jcaAlg, final Provider provider)
			throws JOSEException {
		return getSignerAndVerifier(jcaAlg, provider, null);
	}

	private static Signature getSignerAndVerifier(final String jcaAlg, final Provider provider, final PSSParameterSpec pssSpec)
			throws JOSEException {

		Signature signature;
		try {
			if (provider != null) {
				signature = Signature.getInstance(jcaAlg, provider);
			} else {
				signature = Signature.getInstance(jcaAlg);
			}
		} catch (NoSuchAlgorithmException ignore) {
			return null;
		}

		if (pssSpec != null) {
			try {
				signature.setParameter(pssSpec);
			} catch (InvalidAlgorithmParameterException e) {
				throw new JOSEException("Invalid RSASSA-PSS salt length parameter: " + e.getMessage(), e);
			}
		}

		return signature;
	}

	/**
	 * Prevents public instantiation.
	 */
	private RSASSA() {

	}
}
