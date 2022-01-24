/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
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

package com.nimbusds.jose.jwk.source;


import java.io.FileNotFoundException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static net.jadler.Jadler.*;
import static org.junit.Assert.*;

import net.jadler.Request;
import net.jadler.stubbing.Responder;
import net.jadler.stubbing.StubResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.StandardCharset;


public class RemoteJWKSetTest {



	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
		
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout");
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout");
		System.clearProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit");
	}


	@Test
	public void testConstants() {
		assertEquals(500, RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT);
		assertEquals(500, RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT);
		assertEquals(50 * 1024, RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT);
	}


	@Test
	public void testSimplifiedConstructor()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList(rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody( JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL, null);

		assertTrue(jwkSetSource.getResourceRetriever() instanceof DefaultResourceRetriever);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());
		assertTrue(jwkSetSource.getJWKSetCache() instanceof DefaultJWKSetCache);
		assertNull(jwkSetSource.getCachedJWKSet());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		JWKSet out = jwkSetSource.getCachedJWKSet();
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());
	}


	@Test
	public void testSelectRSAByKeyID_defaultRetriever()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList(rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL, null);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());
		assertNull(jwkSetSource.getCachedJWKSet());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	@Test
	public void testRefreshRSAByKeyID_defaultRetriever()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		keyPair = pairGen.generateKeyPair();

		final RSAKey rsaJWK3 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("3")
			.build();

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respondUsing(new Responder() {
				private int count = 0;
				@Override
				public StubResponse nextResponse(Request request) {

					if (! request.getMethod().equalsIgnoreCase("GET")) {
						return StubResponse.builder().status(405).build();
					}

					if (count == 0) {
						++count;
						return StubResponse.builder()
							.status(200)
							.header("Content-Type", "application/json")
							.body( JSONObjectUtils.toJSONString(new JWKSet(Arrays.asList(rsaJWK1, (JWK)rsaJWK2)).toJSONObject()), StandardCharset.UTF_8)
							.build();
					}

					// Add 3rd key
					return StubResponse.builder()
						.status(200)
						.header("Content-Type", "application/json")
						.body( JSONObjectUtils.toJSONString(new JWKSet(Arrays.asList(rsaJWK1, rsaJWK2, (JWK)rsaJWK3)).toJSONObject()), StandardCharset.UTF_8)
						.build();
				}
			});

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL, null);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());
		assertNotNull(jwkSetSource.getResourceRetriever());
		assertNull(jwkSetSource.getCachedJWKSet());

		List<JWK> matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);

		RSAKey m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK1.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK1.getModulus(), m1.getModulus());
		assertEquals("1", m1.getKeyID());

		assertEquals(1, matches.size());

		// Check cache
		JWKSet out = jwkSetSource.getCachedJWKSet();
		assertTrue(out.getKeys().get(0) instanceof RSAKey);
		assertTrue(out.getKeys().get(1) instanceof RSAKey);
		assertEquals("1", out.getKeys().get(0).getKeyID());
		assertEquals("2", out.getKeys().get(1).getKeyID());
		assertEquals(2, out.getKeys().size());

		// Select 3rd key, expect refresh of JWK set
		matches = jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("3").build()), null);

		m1 = (RSAKey) matches.get(0);
		assertEquals(rsaJWK3.getPublicExponent(), m1.getPublicExponent());
		assertEquals(rsaJWK3.getModulus(), m1.getModulus());
		assertEquals("3", m1.getKeyID());

		assertEquals(1, matches.size());
	}


	@Test
	public void testInvalidJWKSetURL()
		throws Exception {

		KeyPairGenerator pairGen = KeyPairGenerator.getInstance("RSA");
		pairGen.initialize(1024);
		KeyPair keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("1")
			.build();

		keyPair = pairGen.generateKeyPair();

		RSAKey rsaJWK2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID("2")
			.build();

		JWKSet jwkSet = new JWKSet(Arrays.asList(rsaJWK1, (JWK)rsaJWK2));

		URL jwkSetURL = new URL("http://localhost:" + port() + "/invalid-path");

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/jwks.json")
			.respond()
			.withStatus(200)
			.withHeader("Content-Type", "application/json")
			.withBody(JSONObjectUtils.toJSONString(jwkSet.toJSONObject(true)));

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL, null);

		assertEquals(jwkSetURL, jwkSetSource.getJWKSetURL());

		assertNull(jwkSetSource.getCachedJWKSet());

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().keyID("1").build()), null);
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: " + jwkSetURL, e.getMessage());
			assertTrue(e.getCause() instanceof FileNotFoundException);
			assertEquals(jwkSetURL.toString(), e.getCause().getMessage());
		}
	}


	@Test
	public void testTimeout()
		throws Exception {

		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest().respond().withDelay(800, TimeUnit.MILLISECONDS);

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL);

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			fail();
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: Read timed out", e.getMessage());
			assertTrue(e.getCause() instanceof SocketTimeoutException);
			assertEquals("Read timed out", e.getCause().getMessage());
		}
	}


	@Test
	public void testResolveDefaults() {
		
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT, RemoteJWKSet.resolveDefaultHTTPConnectTimeout());
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT, RemoteJWKSet.resolveDefaultHTTPReadTimeout());
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT, RemoteJWKSet.resolveDefaultHTTPSizeLimit());
	}


	@Test
	public void testResolveDefaults_systemPropertyOverride() {
		
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "250");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "100");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "10000");
		
		assertEquals(250, RemoteJWKSet.resolveDefaultHTTPConnectTimeout());
		assertEquals(100, RemoteJWKSet.resolveDefaultHTTPReadTimeout());
		assertEquals(10_000, RemoteJWKSet.resolveDefaultHTTPSizeLimit());
	}


	@Test
	public void testDefaultsSetBySystemProperties_readTimeout()
		throws Exception {

		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "250");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "100");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "10000");
		
		URL jwkSetURL = new URL("http://localhost:" + port() + "/jwks.json");

		onRequest().respond().withDelay(350, TimeUnit.MILLISECONDS);

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL);
		
		assertEquals(250, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getConnectTimeout());
		assertEquals(100, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getReadTimeout());
		assertEquals(10_000, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getSizeLimit());

		try {
			jwkSetSource.get(new JWKSelector(new JWKMatcher.Builder().build()), null);
			fail();
		} catch (RemoteKeySourceException e) {
			assertEquals("Couldn't retrieve remote JWK set: Read timed out", e.getMessage());
			assertTrue(e.getCause() instanceof SocketTimeoutException);
			assertEquals("Read timed out", e.getCause().getMessage());
		}
	}


	@Test
	public void testDefaultsSetBySystemProperties_ignoreNumberFormatExceptions()
		throws Exception {

		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpConnectTimeout", "aaa");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpReadTimeout", "bbb");
		System.setProperty("com.nimbusds.jose.jwk.source.RemoteJWKSet.defaultHttpSizeLimit", "ccc");
		
		URL jwkSetURL = new URL("https://example.com/jwks.json");

		RemoteJWKSet<?> jwkSetSource = new RemoteJWKSet<>(jwkSetURL);
		
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_CONNECT_TIMEOUT, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getConnectTimeout());
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_READ_TIMEOUT, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getReadTimeout());
		assertEquals(RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT, ((DefaultResourceRetriever)jwkSetSource.getResourceRetriever()).getSizeLimit());
	}
}
