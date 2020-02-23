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

package com.nimbusds.jose.util;


import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;

import junit.framework.TestCase;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.junit.Assert;


/**
 * Tests the X.509 certificate utilities.
 */
public class X509CertUtilsTest extends TestCase {
	

	private static final String PEM_CERT =
		"-----BEGIN CERTIFICATE-----" +
		"MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV" +
		"BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow" +
		"GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz" +
		"LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1" +
		"cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN" +
		"MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0" +
		"ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC" +
		"AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX" +
		"57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB" +
		"1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL" +
		"HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED" +
		"pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb" +
		"GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T" +
		"AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/" +
		"BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v" +
		"Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG" +
		"AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv" +
		"cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k" +
		"YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk" +
		"ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD" +
		"MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u" +
		"bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG" +
		"SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln" +
		"2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M" +
		"l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN" +
		"KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP" +
		"63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ" +
		"X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy" +
		"-----END CERTIFICATE-----";


	private static final String PEM_CERT_WITH_WHITESPACE =
		"-----BEGIN CERTIFICATE-----\n" +
		"MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV\n" +
		"BAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMRow\n" +
		"GAYDVQQKExFHb0RhZGR5LmNvbSwgSW5jLjEtMCsGA1UECxMkaHR0cDovL2NlcnRz\n" +
		"LmdvZGFkZHkuY29tL3JlcG9zaXRvcnkvMTMwMQYDVQQDEypHbyBEYWRkeSBTZWN1\n" +
		"cmUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gRzIwHhcNMTUwNDAxMDYyMjM4WhcN\n" +
		"MTYwNDAxMDYyMjM4WjA8MSEwHwYDVQQLExhEb21haW4gQ29udHJvbCBWYWxpZGF0\n" +
		"ZWQxFzAVBgNVBAMTDmNvbm5lY3QyaWQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
		"AQ8AMIIBCgKCAQEAlz+BCaVIkxTPKSmgLLqoEqswUBPHPMu0QVTfk1ixt6s6mvRX\n" +
		"57IsOf4VE/6eXNBvqpbfc6KxH2bAw3E7mbmIBpwCFKbdbYt1hqMn3D3dSAWgYCVB\n" +
		"1f7m1IVxl4lmN55xO7dk27ytOLUgTfFJ6Xg/N4rK2CQCiQaPzzObYvUkVbONplEL\n" +
		"HXBZiu3NxALapEGO89k25D9s85MVk8nYgaBhWBDkW4lDJ4m3Tg5GXgXTHQVM+yED\n" +
		"pWDX0QWFy+8jIG7HEKZOPNMQ5tVMDTaeVPUJHk3N0fiQDAGyg10J4XMaDT9auWcb\n" +
		"GCAao2SPg5Ya82K0tjT4f+sC8nLBXRMMhPE54wIDAQABo4IBtTCCAbEwDAYDVR0T\n" +
		"AQH/BAIwADAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDgYDVR0PAQH/\n" +
		"BAQDAgWgMDYGA1UdHwQvMC0wK6ApoCeGJWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20v\n" +
		"Z2RpZzJzMS04Ny5jcmwwUwYDVR0gBEwwSjBIBgtghkgBhv1tAQcXATA5MDcGCCsG\n" +
		"AQUFBwIBFitodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFkZHkuY29tL3JlcG9zaXRv\n" +
		"cnkvMHYGCCsGAQUFBwEBBGowaDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZ29k\n" +
		"YWRkeS5jb20vMEAGCCsGAQUFBzAChjRodHRwOi8vY2VydGlmaWNhdGVzLmdvZGFk\n" +
		"ZHkuY29tL3JlcG9zaXRvcnkvZ2RpZzIuY3J0MB8GA1UdIwQYMBaAFEDCvSeOzDSD\n" +
		"MKIz1/tss/C0LIDOMC0GA1UdEQQmMCSCDmNvbm5lY3QyaWQuY29tghJ3d3cuY29u\n" +
		"bmVjdDJpZC5jb20wHQYDVR0OBBYEFMyPo6ETFAUYEOtCPxvAH0CTJq4mMA0GCSqG\n" +
		"SIb3DQEBCwUAA4IBAQCWAgw3I4dLkLe/GLrFCtSlcHg/pVZiHEFoTHry6J/GVWln\n" +
		"2CqxZa9vCtKVWzzeRjRg7Nfa/qhnsnJZ+TqsHH5qVDAPUTEufvNAZBV3vzd8kx4M\n" +
		"l+zfgP+mCqagE/S0DMhMrIl6Tx6/s1uQkVdApjBa073FCnJq/rUlCUJfWTvP4xgN\n" +
		"KcztsToQDczLHLr7v8w1JQoHqrKC6K2Tj297nKs097rVFbW/3mHkWLTu30djGJIP\n" +
		"63oxR9Nw7JVZRrH/8On4h4DVwJC5jl+Le1aJm4RgqtVopDukK5ga5kPwteV6erNZ\n" +
		"X9x/niTIBH0P3DOlO7s4eFIIAfuI0JAUF3CmUxBy\n" +
		"-----END CERTIFICATE-----\n";


	public void testParsePEM() {

		X509Certificate cert = X509CertUtils.parse(PEM_CERT);

		assertEquals("X.509", cert.getType());
		assertEquals("CN=connect2id.com,OU=Domain Control Validated", cert.getSubjectX500Principal().getName());
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
	}


	public void testParsePEMWithException()
		throws Exception {

		X509Certificate cert = X509CertUtils.parseWithException(PEM_CERT);

		assertEquals("X.509", cert.getType());
		assertEquals("CN=connect2id.com,OU=Domain Control Validated", cert.getSubjectX500Principal().getName());
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
	}


	public void testParsePEMWithException_noBeginMarker() {

		try {
			X509CertUtils.parseWithException(PEM_CERT.replace("-----BEGIN CERTIFICATE-----", ""));
			fail();
		} catch (CertificateException e) {
			assertEquals("PEM begin marker not found", e.getMessage());
		}
	}


	public void testParsePEMWithException_noEndMarker() {

		try {
			X509CertUtils.parseWithException(PEM_CERT.replace("-----END CERTIFICATE-----", ""));
			fail();
		} catch (CertificateException e) {
			assertEquals("PEM end marker not found", e.getMessage());
		}
	}


	public void testParsePEMWithException_corruptedContent() {

		try {
			X509CertUtils.parseWithException("-----BEGIN CERTIFICATE-----MIIFKjCCBBKgAwIBAgIIM1RIMykkp1AwDQYJKoZIhvcNAQELBQAwgbQxCzAJBgNV-----END CERTIFICATE-----");
			fail();
		} catch (CertificateException e) {
			assertEquals("Could not parse certificate: java.io.IOException: Incomplete BER/DER data", e.getMessage());
		}
	}

	
	public void testParsePEM_withWhitespace() {

		X509Certificate cert = X509CertUtils.parse(PEM_CERT_WITH_WHITESPACE);

		assertEquals("X.509", cert.getType());
		assertEquals("CN=connect2id.com,OU=Domain Control Validated", cert.getSubjectX500Principal().getName());
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
	}
	
	
	public void testParseCertWithECKey()
		throws Exception {
		
		String content = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), Charset.forName("UTF-8"));
		
		X509Certificate cert = X509CertUtils.parse(content);
		
		assertTrue(cert.getPublicKey() instanceof ECPublicKey);
		
		// For definition, see rfc2459, 4.2.1.3 Key Usage
		assertTrue ("Digital signature",       cert.getKeyUsage()[0]);
		assertFalse("Non repudiation",         cert.getKeyUsage()[1]);
		assertFalse("Key encipherment",        cert.getKeyUsage()[2]);
		assertFalse("Data encipherment",       cert.getKeyUsage()[3]);
		assertTrue ("Key agreement",           cert.getKeyUsage()[4]);
		assertFalse("Key certificate signing", cert.getKeyUsage()[5]);
		assertFalse("CRL signing",             cert.getKeyUsage()[6]);
		assertFalse("Decipher",                cert.getKeyUsage()[7]);
		assertFalse("Encipher",                cert.getKeyUsage()[8]);
		
		JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
		
		final String ecPubKeyAlg = "1.2.840.10045.2.1";
		
		assertEquals(ecPubKeyAlg, certHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId());
		assertEquals(Curve.P_256.getOID(), certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString());
	}
	
	
	public void testParseCertWithRSAKey()
		throws Exception {
		
		String content = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), Charset.forName("UTF-8"));
		
		X509Certificate cert = X509CertUtils.parse(content);
		
		assertTrue(cert.getPublicKey() instanceof RSAPublicKey);
		
		// For definition, see rfc2459, 4.2.1.3 Key Usage
		assertTrue ("Digital signature",       cert.getKeyUsage()[0]);
		assertFalse("Non repudiation",         cert.getKeyUsage()[1]);
		assertTrue ("Key encipherment",        cert.getKeyUsage()[2]);
		assertFalse("Data encipherment",       cert.getKeyUsage()[3]);
		assertFalse("Key agreement",           cert.getKeyUsage()[4]);
		assertFalse("Key certificate signing", cert.getKeyUsage()[5]);
		assertFalse("CRL signing",             cert.getKeyUsage()[6]);
		assertFalse("Decipher",                cert.getKeyUsage()[7]);
		assertFalse("Encipher",                cert.getKeyUsage()[8]);
		
		JcaX509CertificateHolder certHolder = new JcaX509CertificateHolder(cert);
		
		final String rsaPubKeyAlg = "1.2.840.113549.1.1.1";
		assertEquals(rsaPubKeyAlg, certHolder.getSubjectPublicKeyInfo().getAlgorithm().getAlgorithm().getId());
		assertEquals("NULL", certHolder.getSubjectPublicKeyInfo().getAlgorithm().getParameters().toString());
	}
	
	
	public void testSHA256Thumbprint()
		throws Exception {
		
		X509Certificate cert = X509CertUtils.parse(PEM_CERT);
		
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte[] hash = sha256.digest(cert.getEncoded());
		assertEquals(256, ByteUtils.bitLength(hash));
		
		Base64URL thumbPrint = X509CertUtils.computeSHA256Thumbprint(cert);
		
		assertEquals(Base64URL.encode(hash), thumbPrint);
	}
	
	
	public void testPEMRoundTrip() {
		
		X509Certificate cert = X509CertUtils.parse(PEM_CERT);
		String pemString = X509CertUtils.toPEMString(cert);
		String[] lines = pemString.split("\\n");
		assertEquals("-----BEGIN CERTIFICATE-----", lines[0]);
		assertEquals("-----END CERTIFICATE-----", lines[2]);
		assertEquals(3, lines.length);
		assertEquals(cert.getSubjectDN(), X509CertUtils.parse(pemString).getSubjectDN());
	}
	
	
	public void testPEMRoundTrip_noLineBreaks() {
		
		X509Certificate cert = X509CertUtils.parse(PEM_CERT);
		String pemString = X509CertUtils.toPEMString(cert, false);
		assertNotNull(pemString);
		assertEquals(-1, pemString.indexOf("\n"));
		assertEquals(cert.getSubjectDN(), X509CertUtils.parse(pemString).getSubjectDN());
	}
	
	
	public void testMarkerConstants() {
		
		assertEquals("-----BEGIN CERTIFICATE-----", X509CertUtils.PEM_BEGIN_MARKER);
		assertEquals("-----END CERTIFICATE-----", X509CertUtils.PEM_END_MARKER);
	}
	
	
	public void testStore_noPassword() throws Exception {
		
		JWK jwk = JWK.parseFromPEMEncodedObjects(IOUtils.readFileToString(new File("src/test/resources/sample-pem-encoded-objects/ecprivkey.pem"), StandardCharset.UTF_8));
		assertTrue(jwk instanceof ECKey);
		ECKey ecJWK = (ECKey)jwk;
		
		X509Certificate cert = X509CertUtils.parse(IOUtils.readFileToString(new File("src/test/resources/sample-pem-encoded-objects/eccert.pem"), StandardCharset.UTF_8));
		
		Assert.assertArrayEquals(ecJWK.toECPublicKey().getEncoded(), cert.getPublicKey().getEncoded());
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		
		UUID alias = X509CertUtils.store(keyStore, ecJWK.toECPrivateKey(), new char[]{0}, cert);
		
		assertNotNull(alias);
	
		KeyStore.Entry en = keyStore.getEntry(alias.toString(), new KeyStore.PasswordProtection(new char[]{0}));
		assertTrue(en instanceof KeyStore.PrivateKeyEntry);
		
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)en;
		
		Assert.assertArrayEquals(ecJWK.toPrivateKey().getEncoded(), privateKeyEntry.getPrivateKey().getEncoded());
		Assert.assertArrayEquals(cert.getEncoded(), privateKeyEntry.getCertificate().getEncoded());
	}
	
	
	public void testStore_withPassword() throws Exception {
		
		JWK jwk = JWK.parseFromPEMEncodedObjects(IOUtils.readFileToString(new File("src/test/resources/sample-pem-encoded-objects/ecprivkey.pem")));
		assertTrue(jwk instanceof ECKey);
		ECKey ecJWK = (ECKey)jwk;
		
		X509Certificate cert = X509CertUtils.parse(IOUtils.readFileToString(new File("src/test/resources/sample-pem-encoded-objects/eccert.pem")));
		
		Assert.assertArrayEquals(ecJWK.toECPublicKey().getEncoded(), cert.getPublicKey().getEncoded());
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		keyStore.load(null);
		
		String password = "secret";
		UUID alias = X509CertUtils.store(keyStore, ecJWK.toECPrivateKey(), password.toCharArray(), cert);
		
		assertNotNull(alias);
	
		KeyStore.Entry en = keyStore.getEntry(alias.toString(), new KeyStore.PasswordProtection(password.toCharArray()));
		assertTrue(en instanceof KeyStore.PrivateKeyEntry);
		
		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)en;
		
		Assert.assertArrayEquals(ecJWK.toPrivateKey().getEncoded(), privateKeyEntry.getPrivateKey().getEncoded());
		Assert.assertArrayEquals(cert.getEncoded(), privateKeyEntry.getCertificate().getEncoded());
	}
}
