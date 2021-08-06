/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd.
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

package com.nimbusds.jose.crypto;


import com.google.crypto.tink.subtle.X25519;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.ECDH;
import com.nimbusds.jose.crypto.impl.ECDH1PU;
import com.nimbusds.jose.crypto.impl.ECDH1PUCryptoProvider;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Collections;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman encrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects} for curves using EC JWK keys.
 * Expects a public {@link OctetKeyPair} key with {@code "crv"} X25519.
 *
 * <p>See <a href="https://tools.ietf.org/html/rfc8037">RFC 8037</a>
 * for more information.
 *
 * <p>See also {@link ECDH1PUEncrypter} for ECDH on other curves.
 *
 * <p>Public Key Authenticated Encryption for JOSE
 * <a href="https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04">ECDH-1PU</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#ECDH_1PU_A256KW}
 * </ul>
 *
 * <p>Supports the following elliptic curves:
 *
 * <ul>
 *     <li>{@link Curve#P_256}
 *     <li>{@link Curve#P_384}
 *     <li>{@link Curve#P_521}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Direct key agreement mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms for Direct Key wrapping mode:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 * </ul>
 *
 * @author Alexander Martynov
 * @version 2021-08-03
 */
@ThreadSafe
public class ECDH1PUX25519Encrypter extends ECDH1PUCryptoProvider implements JWEEncrypter {


	/**
	 * The public key.
	 */
	private final OctetKeyPair publicKey;

	/**
	 * The private key.
	 */
	private final OctetKeyPair privateKey;

	/**
	 * The externally supplied AES content encryption key (CEK) to use,
	 * {@code null} to generate a CEK for each JWE.
	 */
	private final SecretKey contentEncryptionKey;

	/**
	 * Creates a new Curve25519 Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param privateKey The private key. Must not be {@code null}.
	 * @param publicKey The public key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key subtype is not supported.
	 */
	public ECDH1PUX25519Encrypter(final OctetKeyPair privateKey, final OctetKeyPair publicKey)
			throws JOSEException {

		this(privateKey, publicKey, null);
	}

	/**
	 * Creates a new Curve25519 Elliptic Curve Diffie-Hellman encrypter.
	 *
	 * @param privateKey The private key. Must not be {@code null}.
	 * @param publicKey The public key. Must not be {@code null}.
	 * @param contentEncryptionKey The content encryption key (CEK) to use.
	 *                             If specified its algorithm must be "AES"
	 *                             and its length must match the expected
	 *                             for the JWE encryption method ("enc").
	 *                             If {@code null} a CEK will be generated
	 *                             for each JWE.
	 *
	 * @throws JOSEException If the key subtype is not supported.
	 */
	public ECDH1PUX25519Encrypter(final OctetKeyPair privateKey,
								  final OctetKeyPair publicKey,
								  final SecretKey contentEncryptionKey
								  )
			throws JOSEException {

		super(publicKey.getCurve());

		this.publicKey = publicKey;
		this.privateKey = privateKey;

		if (contentEncryptionKey != null && (contentEncryptionKey.getAlgorithm() == null || !contentEncryptionKey.getAlgorithm().equals("AES")))
			throw new IllegalArgumentException("The algorithm of the content encryption key (CEK) must be AES");

		this.contentEncryptionKey = contentEncryptionKey;
	}

	@Override
	public Set<Curve> supportedEllipticCurves() {

		return Collections.singleton(Curve.X25519);
	}


	/**
	 * Returns the public key.
	 *
	 * @return The public key.
	 */
	public OctetKeyPair getPublicKey() {

		return publicKey;
	}

	/**
	 * Returns the private key.
	 *
	 * @return The private key.
	 */
	public OctetKeyPair getPrivateKey() {

		return privateKey;
	}

	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
			throws JOSEException {

		ECDH1PU.validateSameCurve(privateKey, publicKey);

		// Generate ephemeral X25519 key pair
		final byte[] ephemeralPrivateKeyBytes = X25519.generatePrivateKey();
		final byte[] ephemeralPublicKeyBytes;
		try {
			ephemeralPublicKeyBytes = X25519.publicFromPrivate(ephemeralPrivateKeyBytes);

		} catch (InvalidKeyException e) {
			// Should never happen since we just generated this private key
			throw new JOSEException(e.getMessage(), e);
		}

		final OctetKeyPair ephemeralPrivateKey =
				new OctetKeyPair.Builder(getCurve(), Base64URL.encode(ephemeralPublicKeyBytes)).
						d(Base64URL.encode(ephemeralPrivateKeyBytes)).
						build();
		final OctetKeyPair ephemeralPublicKey = ephemeralPrivateKey.toPublicJWK();

		// Add the ephemeral public EC key to the header
		JWEHeader updatedHeader = new JWEHeader.Builder(header).
				ephemeralPublicKey(ephemeralPublicKey).
				build();

		SecretKey Ze = ECDH.deriveSharedSecret(
				publicKey,
				ephemeralPrivateKey);

		SecretKey Zs = ECDH.deriveSharedSecret(
				publicKey,
				privateKey);

		SecretKey Z = ECDH1PU.deriveZ(Ze, Zs);

		return encryptWithZ(updatedHeader, Z, clearText, contentEncryptionKey);
	}
}
