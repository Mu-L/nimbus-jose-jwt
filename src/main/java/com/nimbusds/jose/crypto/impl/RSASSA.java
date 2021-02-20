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

		final String jcaAlg;
		
		// Alternative JCA name to try
		String jcaAlgAlt = null;
		
		PSSParameterSpec pssSpec = null;

		if (alg.equals(JWSAlgorithm.RS256)) {
			
			jcaAlg = "SHA256withRSA";
			
		} else if (alg.equals(JWSAlgorithm.RS384)) {
			
			jcaAlg = "SHA384withRSA";
			
		} else if (alg.equals(JWSAlgorithm.RS512)) {
			
			jcaAlg = "SHA512withRSA";
			
		} else if (alg.equals(JWSAlgorithm.PS256)) {
			
			jcaAlg = "RSASSA-PSS"; // JWA mandates salt length equals hash
			pssSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
			
			jcaAlgAlt = "SHA256withRSAandMGF1";
			
		} else if (alg.equals(JWSAlgorithm.PS384)) {
			
			jcaAlg = "RSASSA-PSS"; // JWA mandates salt length equals hash
			pssSpec = new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
			
			jcaAlgAlt = "SHA384withRSAandMGF1";
			
		} else if (alg.equals(JWSAlgorithm.PS512)) {
			
			jcaAlg = "RSASSA-PSS"; // JWA mandates salt length equals hash
			pssSpec = new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
			
			jcaAlgAlt = "SHA512withRSAandMGF1";
			
		} else {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, RSASSAProvider.SUPPORTED_ALGORITHMS));
		}

		Signature signature;
		try {
			signature = getSignerAndVerifier(jcaAlg, provider);
			
		} catch (NoSuchAlgorithmException e) {
			
			if (jcaAlgAlt == null) {
				throw new JOSEException("Unsupported RSASSA algorithm: " + e.getMessage(), e);
			}
			
			// Retry with alternative JCA name
			try {
				signature = getSignerAndVerifier(jcaAlgAlt, provider);
			} catch (NoSuchAlgorithmException e2) {
				throw new JOSEException("Unsupported RSASSA algorithm (after retry with alternative): " + e2.getMessage(), e2);
			}
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
	
	
	private static Signature getSignerAndVerifier(final String jcaAlg, final Provider provider)
		throws NoSuchAlgorithmException {
		
		if (provider != null) {
			return Signature.getInstance(jcaAlg, provider);
		} else {
			return Signature.getInstance(jcaAlg);
		}
	}


	/**
	 * Prevents public instantiation.
	 */
	private RSASSA() {

	}
}
