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

import static org.junit.Assert.assertEquals;

import java.security.Key;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;

public class MultiAlgorithmKeySelectorTest {
	
	private JWSVerificationKeySelector<SecurityContext> keySelector;
	
	private final String kid1 = UUID.randomUUID().toString();
	private final String kid2 = UUID.randomUUID().toString();
	private final String kid3 = UUID.randomUUID().toString();
	
	private RSAKey signingRS256Jwk;
	private ECKey signingES256Jwk;

	@Before
	public void beforeTests() throws Exception {
		RSAKey fullRSAJwk = new RSAKeyGenerator(2048).keyID(kid1).keyUse(KeyUse.SIGNATURE).generate();
		ECKey fullECJwk = new ECKeyGenerator(Curve.P_256).keyID(kid2).keyUse(KeyUse.SIGNATURE).generate();
		
		signingRS256Jwk = new RSAKey.Builder(fullRSAJwk.toRSAPublicKey()).algorithm(JWSAlgorithm.RS256)
				.keyUse(KeyUse.SIGNATURE).keyID(kid1).build();

		signingES256Jwk = new ECKey.Builder(fullECJwk).algorithm(JWSAlgorithm.ES256)
				.keyUse(KeyUse.SIGNATURE).keyID(kid2).build();

		JWKSource<SecurityContext> jwks = new ImmutableJWKSet<>(new JWKSet(Arrays.<JWK>asList(signingRS256Jwk, signingES256Jwk)));
		
		Set<JWSAlgorithm> algorithms = new HashSet<>(Arrays.asList(JWSAlgorithm.RS256, JWSAlgorithm.RS512, JWSAlgorithm.ES256));
		
		keySelector = new JWSVerificationKeySelector<>(algorithms, jwks);
	}
	
	@Test
	public void selectFromMultipleSupportedAlgorithms() throws Exception {
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid1).build(), null);
		
		assertEquals(1, candidates.size());
		assertEquals(signingRS256Jwk.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(0)).getModulus());
		assertEquals(signingRS256Jwk.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(0)).getPublicExponent());
		
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(kid2).build(), null);
		
		assertEquals(1, candidates.size());
		assertEquals(signingES256Jwk.toECPublicKey().getAlgorithm(), ((ECPublicKey)candidates.get(0)).getAlgorithm());
		assertEquals(signingES256Jwk.toECPublicKey().getParams(), ((ECPublicKey)candidates.get(0)).getParams());
	}

	@Test
	public void doNotSelectAlgorithmThatIsNotAllowed() throws Exception {
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.ES512).keyID(kid3).build(), null);
		assertEquals(0, candidates.size());
	}
}