package com.nimbusds.jose.proc;


import java.security.Key;
import java.util.List;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;

public class SingleKeyJWSKeySelectorTest extends TestCase {
	private final Key key = new SecretKeySpec(new byte[] { 0 }, "mock");
	private final JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
	private final SingleKeyJWSKeySelector<SecurityContext> keySelector =
			new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, this.key);

	public void testThatSelectJWSKeysReturnsKey() {
		JWSHeader jwsHeader = new JWSHeader(this.jwsAlgorithm);
		List<? extends Key> keys = this.keySelector.selectJWSKeys(jwsHeader, null);
		assertEquals(keys.size(), 1);
		assertEquals(keys.get(0), this.key);
	}

	public void testThatSelectJWSKeysVerifiesAlgorithmInHeader() {
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.EdDSA);
		assertTrue("Expected empty list", this.keySelector.selectJWSKeys(jwsHeader, null).isEmpty());
	}

	public void testThatConstructorDoesNotAllowNullAlgorithm() {
		try {
			new SingleKeyJWSKeySelector<>(null, this.key);
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			// pass
		}
	}

	public void testThatConstructorDoesNotAllowNullKeys() {
		try {
			new SingleKeyJWSKeySelector<>(this.jwsAlgorithm, null);
			fail("Expected IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			// pass
		}
	}
}