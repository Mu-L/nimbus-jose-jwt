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


import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.Assert;


public class JWSVerificationKeySelectorTest extends TestCase {
	
	
	static X509Certificate generateCertificate(final String issuer,
						   final String subject,
						   final RSAPublicKey publicKey,
						   final RSAPrivateKey privateKey) {
		
		X500Name certIssuer = new X500Name("cn=" + issuer);
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name certSubject = new X500Name("cn=" + subject);
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			certIssuer,
			serialNumber,
			nbf,
			exp,
			certSubject,
			publicKey
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		
		try {
			X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
			return X509CertUtils.parse(certHolder.getEncoded());
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
	

	public void testForRS256()
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);

		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		Key rsa1 = keyPair.getPublic();
		
		X509Certificate cert = generateCertificate(
			"alice",
			"bob",
			(RSAPublicKey) keyPair.getPublic(),
			(RSAPrivateKey) keyPair.getPrivate()
		);
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(cert.getEncoded());
		Base64URL x5tS256 = Base64URL.encode(md.digest());

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) rsa1)
			.keyID("1")
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.x509CertSHA256Thumbprint(x5tS256)
			.build();

		keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.keyID("2")
			.keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.build();

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
			JWSAlgorithm.RS256,
			new ImmutableJWKSet(new JWKSet(Arrays.asList((JWK)rsaJWK1, (JWK)rsaJWK2))));

		assertTrue(keySelector.isAllowed(JWSAlgorithm.RS256));
		assertEquals(JWSAlgorithm.RS256, keySelector.getExpectedJWSAlgorithm());
		assertNotNull(keySelector.getJWKSource());

		// Test JWK matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build());
		assertTrue(m.getKeyTypes().contains(KeyType.RSA));
		assertTrue(m.getKeyIDs().contains("1"));
		assertTrue(m.getKeyUses().contains(KeyUse.SIGNATURE));
		assertTrue(m.getAlgorithms().contains(JWSAlgorithm.RS256));

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("2").build());
		assertNull(m);

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.HS256).build());
		assertNull(m);

		// Select for good header with key ID
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(), null);

		assertEquals(rsaJWK1.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(0)).getModulus());
		assertEquals(rsaJWK1.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(0)).getPublicExponent());

		assertEquals(1, candidates.size());

		// Select for good header without key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), null);

		assertEquals(rsaJWK1.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(0)).getModulus());
		assertEquals(rsaJWK1.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(0)).getPublicExponent());

		assertEquals(rsaJWK2.toRSAPublicKey().getModulus(), ((RSAPublicKey)candidates.get(1)).getModulus());
		assertEquals(rsaJWK2.toRSAPublicKey().getPublicExponent(), ((RSAPublicKey)candidates.get(1)).getPublicExponent());

		assertEquals(2, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("100").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWS alg
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS384).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with certificate SHA-256 Thumbprint
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).x509CertSHA256Thumbprint(x5tS256).build(), null);
		assertEquals(1, candidates.size());
	}


	public void testForHS256()
		throws Exception {

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
			JWSAlgorithm.HS256,
			new ImmutableJWKSet(new JWKSet(new OctetSequenceKey.Builder(secret).build())));

		assertEquals(JWSAlgorithm.HS256, keySelector.getExpectedJWSAlgorithm());
		assertTrue(keySelector.isAllowed(JWSAlgorithm.HS256));
		assertNotNull(keySelector.getJWKSource());

		// Test JWK matcher
		JWKMatcher m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.HS256).build());
		assertTrue(m.getKeyTypes().contains(KeyType.OCT));
		assertTrue(m.getAlgorithms().contains(JWSAlgorithm.HS256));

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build());
		assertNull(m);

		m = keySelector.createJWKMatcher(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("1").build());
		assertNull(m);

		// Select for good header
		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).build(), null);
		Assert.assertArrayEquals(secret, candidates.get(0).getEncoded());
		assertEquals(1, candidates.size());

		// Select for header with invalid key ID
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("100").build(), null);
		assertTrue(candidates.isEmpty());

		// Select for header with unexpected JWS alg
		candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());
	}

	public void testForUnsupported()
			throws Exception {

		JWSAlgorithm unsupported = JWSAlgorithm.parse("unsupported");

		RSAKey rsa = new RSAKey.Builder(new Base64URL("n"), new Base64URL("e"))
			.algorithm(unsupported)
			.keyID("1")
			.build();

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
			unsupported,
			new ImmutableJWKSet(new JWKSet(rsa))
		);

		List<Key> candidates = keySelector.selectJWSKeys(new JWSHeader.Builder(unsupported).keyID("1").build(), null);
		assertTrue(candidates.isEmpty());
	}

	public void testForBackwardCompatibility() {
		Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
		jwsAlgs.add(JWSAlgorithm.RS256);
		jwsAlgs.add(JWSAlgorithm.RS512);

		RSAKey rsa = new RSAKey.Builder(new Base64URL("n"), new Base64URL("e"))
				.algorithm(JWSAlgorithm.RS256)
				.keyID("1")
				.build();

		JWSVerificationKeySelector keySelector = new JWSVerificationKeySelector(
				jwsAlgs,
				new ImmutableJWKSet(new JWKSet(rsa))
		);

		try {
			keySelector.getExpectedJWSAlgorithm();
			fail("getExpectedJWSAlgorithm should have failed since multiple algorithms " +
					"were specified in the constructor");
		} catch (UnsupportedOperationException e) {
			// pass
		}
	}
}
