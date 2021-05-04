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

package com.nimbusds.jose.jwk;


import java.io.File;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * Tests the base JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2020-04-09
 */
public class JWKTest extends TestCase {
	

	public void testMIMEType() {

		assertEquals("application/jwk+json; charset=UTF-8", JWK.MIME_TYPE);
	}
	
	
	private void validateJWKFromX509Cert(final JWK jwk, final KeyType expectedKeyType) {
		
		assertEquals(expectedKeyType, jwk.getKeyType());
		assertNull(jwk.getAlgorithm());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertNull(jwk.getKeyOperations());
		assertEquals(1, jwk.getX509CertChain().size());
		assertNull(jwk.getX509CertThumbprint());
		assertNotNull(jwk.getX509CertSHA256Thumbprint());
		assertFalse(jwk.isPrivate());
		
		if (KeyType.RSA.equals(expectedKeyType)) {
			assertTrue(jwk instanceof RSAKey);
		} else if (KeyType.EC.equals(expectedKeyType)) {
			assertTrue(jwk instanceof ECKey);
		} else {
			fail();
		}
	}
	
	
	public void testParseRSAJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		validateJWKFromX509Cert(jwk, KeyType.RSA);
	}
	
	
	public void testParseECJWKFromX509Cert()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), Charset.forName("UTF-8"));
		X509Certificate cert = X509CertUtils.parse(pemEncodedCert);
		JWK jwk = JWK.parse(cert);
		validateJWKFromX509Cert(jwk, KeyType.EC);
		assertEquals(Curve.P_256, ((ECKey)jwk).getCurve());
	}
	
	
	public void testParseRSAJWKFromX509Cert_pem()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), Charset.forName("UTF-8"));
		JWK jwk = JWK.parseFromPEMEncodedX509Cert(pemEncodedCert);
		validateJWKFromX509Cert(jwk, KeyType.RSA);
	}
	
	
	public void testParseECJWKFromX509Cert_pem()
		throws Exception {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), Charset.forName("UTF-8"));
		JWK jwk = JWK.parseFromPEMEncodedX509Cert(pemEncodedCert);
		validateJWKFromX509Cert(jwk, KeyType.EC);
		assertEquals(Curve.P_256, ((ECKey)jwk).getCurve());
	}
	
	
	public void testLoadRSAJWKFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(1024);
		KeyPair kp = gen.generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey)kp.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey)kp.getPrivate();
		
		// Generate certificate
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new Certificate[]{cert});
		
		// Load
		RSAKey rsaKey = (RSAKey) JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(rsaKey);
		assertEquals(KeyUse.SIGNATURE, rsaKey.getKeyUse());
		assertEquals("1", rsaKey.getKeyID());
		assertEquals(1, rsaKey.getX509CertChain().size());
		assertNull(rsaKey.getX509CertThumbprint());
		assertNotNull(rsaKey.getX509CertSHA256Thumbprint());
		assertTrue(rsaKey.isPrivate());
		
		// Try to load with bad pin
		try {
			JWK.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().startsWith("Couldn't retrieve private RSA key (bad pin?)"));
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadECJWKFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		// Generate key pair
		KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
		gen.initialize(Curve.P_521.toECParameterSpec());
		KeyPair kp = gen.generateKeyPair();
		ECPublicKey publicKey = (ECPublicKey)kp.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey)kp.getPrivate();
		
		// Generate certificate
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			publicKey
		);
		KeyUsage keyUsage = new KeyUsage(KeyUsage.nonRepudiation);
		x509certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withECDSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(privateKey));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		// Store
		keyStore.setKeyEntry("1", privateKey, "1234".toCharArray(), new java.security.cert.Certificate[]{cert});
		
		// Load
		ECKey ecKey = (ECKey)JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(ecKey);
		assertEquals(Curve.P_521, ecKey.getCurve());
		assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
		assertEquals("1", ecKey.getKeyID());
		assertEquals(1, ecKey.getX509CertChain().size());
		assertNull(ecKey.getX509CertThumbprint());
		assertNotNull(ecKey.getX509CertSHA256Thumbprint());
		assertTrue(ecKey.isPrivate());
		
		// Try to load with bad pin
		try {
			JWK.load(keyStore, "1", "".toCharArray());
			fail();
		} catch (JOSEException e) {
			assertTrue(e.getMessage().startsWith("Couldn't retrieve private EC key (bad pin?)"));
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}
	
	
	public void testLoadSecretKeyFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey secretKey = gen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		OctetSequenceKey octJWK = (OctetSequenceKey)JWK.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(octJWK);
		assertEquals("1", octJWK.getKeyID());
		assertTrue(Arrays.equals(secretKey.getEncoded(), octJWK.toByteArray()));
	}
	
	
	public void testLoadJWK_notFound()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		assertNull(JWK.load(keyStore, "no-such-key-id", "".toCharArray()));
	}
	
	
	public void testParseOKP()
		throws Exception {
		
		String json = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
		
		JWK jwk = JWK.parse(json);
		assertEquals(KeyType.OKP, jwk.getKeyType());
		
		OctetKeyPair okp = (OctetKeyPair)jwk;
		
		assertEquals(Curve.X448, okp.getCurve());
		assertEquals("PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk", okp.getX().toString());
		assertEquals("Dave", okp.getKeyID());
		assertFalse(okp.isPrivate());
	}

	public void testParsePemRsaPublicKey() throws JOSEException {
		RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PUBLIC_KEY_PEM);
		assertEquals(KeyType.RSA, rsaKey.getKeyType());
		assertFalse(rsaKey.isPrivate());
	}

	public void testParsePemRsaPublicKeyFromCert() throws JOSEException {
		RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_CERT_PEM);
		assertEquals(KeyType.RSA, rsaKey.getKeyType());
		assertFalse(rsaKey.isPrivate());
	}

	public void testParsePemRsaPrivateKey() throws JOSEException {
		RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);
		assertEquals(KeyType.RSA, rsaKey.getKeyType());
		assertTrue(rsaKey.isPrivate());
		assertNotNull(rsaKey.getModulus());
		assertNotNull(rsaKey.getPrivateExponent());
		assertNotNull(rsaKey.getFirstCRTCoefficient());
		assertNotNull(rsaKey.getFirstFactorCRTExponent());
		assertNotNull(rsaKey.getFirstPrimeFactor());
	}

	public void testParsePemRsaPrivateKeyPlusCert() throws JOSEException {
		RSAKey rsaKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_CERT_PEM + "\r\n" + SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);
		assertEquals(KeyType.RSA, rsaKey.getKeyType());
		assertTrue(rsaKey.isPrivate());
	}


	public void testParsePemEcPublicKey() throws JOSEException {
		ECKey ecKey = (ECKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.EC_PUBLIC_KEY_PEM);
		assertEquals(KeyType.EC, ecKey.getKeyType());
		assertFalse(ecKey.isPrivate());
	}

	public void testParsePemEcPublicKeyFromCert() throws JOSEException {
		ECKey ecKey = (ECKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.EC_CERT_PEM);
		assertEquals(KeyType.EC, ecKey.getKeyType());
		assertFalse(ecKey.isPrivate());
	}

	public void testParsePemEcPrivateKey() throws JOSEException {
		ECKey ecKey = (ECKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.EC_PRIVATE_KEY_PEM);
		assertEquals(KeyType.EC, ecKey.getKeyType());
		assertTrue(ecKey.isPrivate());
		assertNotNull(ecKey.getD());
	}

	public void testParsePemEcPrivateKeyPlusCert() throws JOSEException {
		ECKey ecKey = (ECKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.EC_CERT_PEM + "\r\n" + SamplePEMEncodedObjects.EC_PRIVATE_KEY_PEM);
		assertEquals(KeyType.EC, ecKey.getKeyType());
		assertTrue(ecKey.isPrivate());
	}

	public void testPemRoundtripSignVerify() throws JOSEException, ParseException {
		RSAKey signingKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);
		RSAKey validationKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PUBLIC_KEY_PEM);

		JWSSigner signer = new RSASSASigner(signingKey);

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.issuer("https://c2id.com")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000))
				.build();

		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader(JWSAlgorithm.RS256),
				claimsSet);

		// Compute the RSA signature
		signedJWT.sign(signer);

		String s = signedJWT.serialize();

		// On the consumer side, parse the JWS and verify its RSA signature
		signedJWT = SignedJWT.parse(s);

		JWSVerifier verifier = new RSASSAVerifier(validationKey);
		assertTrue(signedJWT.verify(verifier));
	}

	public void testPemRoundtripSignVerifyMismatch()
			throws JOSEException, ParseException, NoSuchAlgorithmException {

		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		keyGenerator.initialize(2048);

		KeyPair kp = keyGenerator.genKeyPair();
		RSAPublicKey wrongValidationKey = (RSAPublicKey)kp.getPublic();

		RSAKey signingKey = (RSAKey) JWK.parseFromPEMEncodedObjects(SamplePEMEncodedObjects.RSA_PRIVATE_KEY_PEM);

		JWSSigner signer = new RSASSASigner(signingKey);

		// Prepare JWT with claims set
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.issuer("https://c2id.com")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000))
				.build();

		SignedJWT signedJWT = new SignedJWT(
				new JWSHeader(JWSAlgorithm.RS256),
				claimsSet);

		// Compute the RSA signature
		signedJWT.sign(signer);

		String s = signedJWT.serialize();

		// On the consumer side, parse the JWS and verify its RSA signature
		signedJWT = SignedJWT.parse(s);

		JWSVerifier verifier = new RSASSAVerifier(wrongValidationKey);
		assertFalse(signedJWT.verify(verifier));
	}
	
	
	public void testParseFromSamplePEM_ecPrivateKeyOnly() throws JOSEException {
		
		String pem = "-----BEGIN PRIVATE KEY-----\r\n" +
			"MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgggR65IgPRgD" +
			"X5Nc52PRJVdXPiv1v8l6c77a8e6fYOk6hRANCAATEu19KZ8mYcyInK6" +
			"k3yGC4bTbjw9/v/32vppEmvKWgZK/2KVOKS+e9IZVVn+bTvtYXLhWGO" +
			"fgrRBuOvV9d0tJm\r\n" +
			"-----END PRIVATE KEY-----";
		
		try {
			JWK.parseFromPEMEncodedObjects(pem);
			fail();
		} catch (JOSEException e) {
			assertEquals("Missing PEM-encoded public key to construct JWK", e.getMessage());
		}
	}
	
	
	public void testCastMethods()
		throws Exception {
		
		JWK jwk = new RSAKeyGenerator(2048).generate();
		RSAKey rsaKey = jwk.toRSAKey();
		assertEquals(jwk, rsaKey);
		
		jwk = new ECKeyGenerator(Curve.P_256).generate();
		ECKey ecKey = jwk.toECKey();
		assertEquals(jwk, ecKey);
		
		jwk = new OctetSequenceKeyGenerator(128).generate();
		OctetSequenceKey oct = jwk.toOctetSequenceKey();
		assertEquals(jwk, oct);
		
		jwk = new OctetKeyPairGenerator(Curve.Ed25519).generate();
		OctetKeyPair okp = jwk.toOctetKeyPair();
		assertEquals(jwk, okp);
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/355/parsing-of-key_ops-from-jwk-output
	public void testParseKeyOps()
		throws Exception {
		
		RSAKey rsaKey = new RSAKeyGenerator(2048)
			.keyOperations(Collections.singleton(KeyOperation.VERIFY))
			.generate();
		
		RSAKey parsed = RSAKey.parse(rsaKey.toJSONObject());
		
		assertEquals(rsaKey.getKeyOperations(), parsed.getKeyOperations());
	}
}
