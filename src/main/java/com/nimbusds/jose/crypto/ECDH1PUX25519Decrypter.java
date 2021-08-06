/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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


import com.nimbusds.jose.CriticalHeaderParamsAware;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.Collections;
import java.util.Set;


/**
 * Elliptic Curve Diffie-Hellman decrypter of
 * {@link com.nimbusds.jose.JWEObject JWE objects} for curves using EC JWK
 * Expects a private {@link OctetKeyPair} key with {@code "crv"} X25519.
 *
 * <p>See <a href="https://tools.ietf.org/html/rfc8037">RFC 8037</a>
 * for more information.
 *
 * <p>See also {@link ECDH1PUDecrypter} for ECDH on other curves.
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
 *     <li>{@link Curve#X25519}
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
 * <p>Supports the following content encryption algorithms for Key wrapping mode:
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
public class ECDH1PUX25519Decrypter extends ECDH1PUCryptoProvider implements JWEDecrypter, CriticalHeaderParamsAware {


	/**
	 * The private key.
	 */
	private final OctetKeyPair privateKey;

	/**
	 * The public key.
	 */
	private final OctetKeyPair publicKey;

	/**
	 * The critical header policy.
	 */
	private final CriticalHeaderParamsDeferral critPolicy = new CriticalHeaderParamsDeferral();


	/**
	 * Creates a new Curve25519 Elliptic Curve Diffie-Hellman decrypter.
	 *
	 * @param privateKey The private key. Must not be {@code null}.
	 * @param publicKey The private key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the key subtype is not supported.
	 */
	public ECDH1PUX25519Decrypter(final OctetKeyPair privateKey, final OctetKeyPair publicKey)
			throws JOSEException {

		this(privateKey, publicKey, null);
	}


	/**
	 * Creates a new Curve25519 Elliptic Curve Diffie-Hellman decrypter.
	 *
	 * @param privateKey     The private key. Must not be {@code null}.
	 * @param publicKey The private key. Must not be {@code null}.
	 * @param defCritHeaders The names of the critical header parameters
	 *                       that are deferred to the application for
	 *                       processing, empty set or {@code null} if none.
	 *
	 * @throws JOSEException If the key subtype is not supported.
	 */
	public ECDH1PUX25519Decrypter(final OctetKeyPair privateKey,
								  final OctetKeyPair publicKey,
								  final Set<String> defCritHeaders)
			throws JOSEException {

		super(privateKey.getCurve());

		this.privateKey = privateKey;
		this.publicKey = publicKey;

		critPolicy.setDeferredCriticalHeaderParams(defCritHeaders);
	}


	@Override
	public Set<Curve> supportedEllipticCurves() {

		return Collections.singleton(Curve.X25519);
	}


	/**
	 * Returns the private key.
	 *
	 * @return The private key.
	 */
	public OctetKeyPair getPrivateKey() {

		return privateKey;
	}

	/**
	 * Returns the public key.
	 *
	 * @return The public key.
	 */
	public OctetKeyPair getPublicKey() {

		return publicKey;
	}

	@Override
	public Set<String> getProcessedCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public Set<String> getDeferredCriticalHeaderParams() {

		return critPolicy.getProcessedCriticalHeaderParams();
	}


	@Override
	public byte[] decrypt(final JWEHeader header,
						  final Base64URL encryptedKey,
						  final Base64URL iv,
						  final Base64URL cipherText,
						  final Base64URL authTag)
			throws JOSEException {

		ECDH1PU.validateSameCurve(privateKey, publicKey);

		// Check for unrecognizable "crit" properties
		critPolicy.ensureHeaderPasses(header);

		// Get ephemeral key from header
		OctetKeyPair ephemeralPublicKey = (OctetKeyPair) header.getEphemeralPublicKey();

		if (ephemeralPublicKey == null) {
			throw new JOSEException("Missing ephemeral public key \"epk\" JWE header parameter");
		}

		ECDH1PU.validateSameCurve(privateKey, ephemeralPublicKey);

		SecretKey Ze = ECDH.deriveSharedSecret(
				ephemeralPublicKey,
				privateKey);

		SecretKey Zs = ECDH.deriveSharedSecret(
				publicKey,
				privateKey);

		// Derive 'Z'
		// Note: X25519 does not require public key validation
		// See https://cr.yp.to/ecdh.html#validate
		SecretKey Z = ECDH1PU.deriveZ(Ze, Zs);

		return decryptWithZ(header, Z, encryptedKey, iv, cipherText, authTag);
	}


}
