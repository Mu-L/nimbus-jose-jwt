package com.nimbusds.jwt.mint;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import junit.framework.TestCase;

public class DefaultJWSMinterTest extends TestCase {
	public void testConstructor() {

		ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();

		assertTrue(minter.getJWSSignerFactory() instanceof DefaultJWSSignerFactory);
		assertNull(minter.getJWKSource());
	}


	public void testMintRoundTrip()
			throws Exception {

		OctetSequenceKeyGenerator generator = new OctetSequenceKeyGenerator(256);
		OctetSequenceKey key = generator.generate();
		JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(key));

		ConfigurableJWSMinter<SecurityContext> minter = new DefaultJWSMinter<>();
		minter.setJWKSource(jwkSource);

		JWTClaimsSet claimsIn = new JWTClaimsSet.Builder()
				.issuer("https://openid.c2id.com")
				.subject("alice")
				.build();
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256)
				.type(JOSEObjectType.JWT)
				.build();

		String jws = minter.mint(header, claimsIn, null);

		ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
		processor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.HS256, jwkSource));
		JWTClaimsSet claimsOut = processor.process(jws, null);
		assertEquals(claimsOut.getIssuer(), claimsIn.getIssuer());
		assertEquals(claimsOut.getSubject(), claimsIn.getSubject());
	}
}
