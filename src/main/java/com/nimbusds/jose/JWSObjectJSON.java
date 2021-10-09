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

package com.nimbusds.jose;


import java.text.ParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

import net.jcip.annotations.Immutable;
import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * JSON Web Signature (JWS) secured object serialisable to
 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-3.2">JSON</a>.
 *
 * <p>This class is thread-safe.
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-10-09
 */
@ThreadSafe
public class JWSObjectJSON extends JOSEObjectJSON {
	
	
	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Individual signature in a JWS secured object serialisable to JSON.
	 */
	@Immutable
	public static final class Signature {
		
		
		/**
		 * The payload.
		 */
		private final Payload payload;
		
		
		/**
		 * The JWS protected header, {@code null} if none.
		 */
		private final JWSHeader header;
		
		
		/**
		 * The unprotected header, {@code null} if none.
		 */
		private final UnprotectedHeader unprotectedHeader;
		
		
		/**
		 * The signature.
		 */
		private final Base64URL signature;
		
		
		/**
		 * The signature verified state.
		 */
		private final AtomicBoolean verified = new AtomicBoolean(false);
		
		
		/**
		 * Creates a new parsed signature.
		 *
		 * @param payload           The payload. Must not be
		 *                          {@code null}.
		 * @param header            The JWS protected header,
		 *                          {@code null} if none.
		 * @param unprotectedHeader The unprotected header,
		 *                          {@code null} if none.
		 * @param signature         The signature. Must not be
		 *                          {@code null}.
		 */
		private Signature(final Payload payload,
				  final JWSHeader header,
				  final UnprotectedHeader unprotectedHeader,
				  final Base64URL signature) {
			
			Objects.requireNonNull(payload);
			this.payload = payload;
			
			this.header = header;
			this.unprotectedHeader = unprotectedHeader;
			
			Objects.requireNonNull(signature);
			this.signature = signature;
		}
		
		
		/**
		 * Returns the JWS protected header.
		 *
		 * @return The JWS protected, {@code null} if none.
		 */
		public JWSHeader getHeader() {
			return header;
		}
		
		
		/**
		 * Returns the unprotected header.
		 *
		 * @return The unprotected header, {@code null} if none.
		 */
		public UnprotectedHeader getUnprotectedHeader() {
			return unprotectedHeader;
		}
		
		
		/**
		 * Returns the signature.
		 *
		 * @return The signature.
		 */
		public Base64URL getSignature() {
			return signature;
		}
		
		
		/**
		 * Returns a JSON object representation for use in the general
		 * and flattened serialisations.
		 *
		 * @return The JSON object.
		 */
		private Map<String, Object> toJSONObject() {
			
			Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
			
			if (header != null) {
				jsonObject.put("protected", header.toBase64URL().toString());
			}
			
			if (unprotectedHeader != null && ! unprotectedHeader.getIncludedParams().isEmpty()) {
				jsonObject.put("header", unprotectedHeader.toJSONObject());
			}
			
			jsonObject.put("signature", signature.toString());
			
			return jsonObject;
		}
		
		
		/**
		 * Returns the compact JWS object representation of this
		 * individual signature.
		 *
		 * @return The JWS object serialisable to compact encoding.
		 */
		public JWSObject toJWSObject() {
			
			try {
				return new JWSObject(header.toBase64URL(), payload.toBase64URL(), signature);
			} catch (ParseException e) {
				throw new IllegalStateException();
			}
		}
		
		
		/**
		 * Returns {@code true} if the signature was successfully
		 * verified with a previous call to {@link #verify}.
		 *
		 * @return {@code true} if the signature was successfully
		 *         verified, {@code false} if the signature is invalid
		 *         or {@link #verify} was never called.
		 */
		public boolean isVerified() {
			return verified.get();
		}
		
		
		/**
		 * Checks the signature with the specified verifier.
		 *
		 * @param verifier The JWS verifier. Must not be {@code null}.
		 *
		 * @return {@code true} if the signature was successfully
		 *         verified, else {@code false}.
		 *
		 * @throws JOSEException If the signature verification failed.
		 */
		public synchronized boolean verify(final JWSVerifier verifier)
			throws JOSEException {
			
			try {
				verified.set(toJWSObject().verify(verifier));
			} catch (JOSEException e) {
				throw e;
			} catch (Exception e) {
				// Prevent throwing unchecked exceptions at this point,
				// see issue #20
				throw new JOSEException(e.getMessage(), e);
			}
			
			return verified.get();
		}
	}
	
	
	/**
	 * Enumeration of the states of a JSON Web Signature (JWS) secured
	 * object serialisable to JSON.
	 */
	public enum State {
		
		
		/**
		 * The object is not signed yet.
		 */
		UNSIGNED,
		
		
		/**
		 * The object has one or more signatures; they are not (all)
		 * verified.
		 */
		SIGNED,
		
		
		/**
		 * All signatures are verified.
		 */
		VERIFIED
	}
	
	
	/**
	 * The applied signatures.
	 */
	private final List<Signature> signatures = new LinkedList<>();
	
	
	/**
	 * Creates a new to-be-signed JSON Web Signature (JWS) secured object
	 * with the specified payload.
	 *
	 * @param payload The payload. Must not be {@code null}.
	 */
	public JWSObjectJSON(final Payload payload) {
		
		super(payload);
		Objects.requireNonNull(payload, "The payload must not be null");
	}
	
	
	/**
	 * Creates a new JSON Web Signature (JWS) secured object with one or
	 * more signatures.
	 *
	 * @param payload    The payload. Must not be {@code null}.
	 * @param signatures The signatures. Must be at least one.
	 */
	private JWSObjectJSON(final Payload payload,
			      final List<Signature> signatures) {
		
		super(payload);
		
		Objects.requireNonNull(payload, "The payload must not be null");
		
		if (signatures.isEmpty()) {
			throw new IllegalArgumentException("At least one signature required");
		}
		
		this.signatures.addAll(signatures);
	}
	
	
	/**
	 * Returns the individual signatures.
	 *
	 * @return The individual signatures, as an unmodified list, empty list
	 *         if none have been added.
	 */
	public List<Signature> getSignatures() {
		
		return Collections.unmodifiableList(signatures);
	}
	
	
	/**
	 * Signs this JWS secured object with the specified JWS signer and
	 * adds the resulting signature to it. To add multiple
	 * {@link #getSignatures() signatures} call this method successively.
	 *
	 * @param jwsHeader The JWS protected header. The algorithm specified
	 *                  by the header must be supported by the JWS signer.
	 *                  Must not be {@code null}.
	 * @param signer    The JWS signer. Must not be {@code null}.
	 *
	 * @throws JOSEException If the JWS object couldn't be signed.
	 */
	public synchronized void sign(final JWSHeader jwsHeader,
				      final JWSSigner signer)
		throws JOSEException {
		
		sign(jwsHeader, null, signer);
	}
	
	
	/**
	 * Signs this JWS secured object with the specified JWS signer and
	 * adds the resulting signature to it. To add multiple
	 * {@link #getSignatures() signatures} call this method successively.
	 *
	 * @param jwsHeader              The JWS protected header. The
	 *                               algorithm specified by the header must
	 *                               be supported by the JWS signer. Must
	 *                               not be {@code null}.
	 * @param unprotectedHeader      The unprotected header to include,
	 *                               {@code null} if none.
	 * @param signer                 The JWS signer. Must not be
	 *                               {@code null}.
	 *
	 * @throws JOSEException If the JWS object couldn't be signed.
	 */
	public synchronized void sign(final JWSHeader jwsHeader,
				      final UnprotectedHeader unprotectedHeader,
				      final JWSSigner signer)
		throws JOSEException {
		
		try {
			HeaderValidation.ensureDisjoint(jwsHeader, unprotectedHeader);
		} catch (IllegalHeaderException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		
		JWSObject jwsObject = new JWSObject(jwsHeader, getPayload());
		jwsObject.sign(signer);
		
		signatures.add(new Signature(getPayload(), jwsHeader, unprotectedHeader, jwsObject.getSignature()));
	}
	
	
	/**
	 * Returns the current signatures state.
	 *
	 * @return The state.
	 */
	public State getState() {
		
		if (getSignatures().isEmpty()) {
			return State.UNSIGNED;
		}
		
		for (Signature sig: getSignatures()) {
			if (! sig.isVerified()) {
				return State.SIGNED;
			}
		}
		
		return State.VERIFIED;
	}
	
	
	@Override
	public Map<String, Object> toGeneralJSONObject() {
		
		if (signatures.size() < 1) {
			throw new IllegalStateException("The general JWS JSON serialization requires at least one signature");
		}
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("payload", getPayload().toBase64URL().toString());
		
		List<Object> signaturesJSONArray = JSONArrayUtils.newJSONArray();
		
		for (Signature signature: getSignatures()) {
			Map<String, Object> signatureJSONObject = signature.toJSONObject();
			signaturesJSONArray.add(signatureJSONObject);
		}
		
		jsonObject.put("signatures", signaturesJSONArray);
		
		return jsonObject;
	}
	
	
	@Override
	public Map<String, Object> toFlattenedJSONObject() {
		
		if (signatures.size() != 1) {
			throw new IllegalStateException("The flattened JWS JSON serialization requires exactly one signature");
		}
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put("payload", getPayload().toBase64URL().toString());
		jsonObject.putAll(getSignatures().get(0).toJSONObject());
		return jsonObject;
	}
	
	
	@Override
	public String serializeGeneral() {
		return JSONObjectUtils.toJSONString(toGeneralJSONObject());
	}
	
	
	@Override
	public String serializeFlattened() {
		return JSONObjectUtils.toJSONString(toFlattenedJSONObject());
	}
	
	
	private static JWSHeader parseJWSHeader(final Map<String, Object> jsonObject)
		throws ParseException {
		
		Base64URL protectedHeader = JSONObjectUtils.getBase64URL(jsonObject, "protected");
		
		if (protectedHeader == null) {
			throw new ParseException("Missing protected header (required by this library)", 0);
		}
		
		try {
			return JWSHeader.parse(protectedHeader);
		} catch (ParseException e) {
			if ("Not a JWS header".equals(e.getMessage())) {
				// alg required by this library (not the spec)
				throw new ParseException("Missing JWS \"alg\" parameter in protected header (required by this library)", 0);
			}
			throw e;
		}
	}
	
	
	/**
	 * Parses a JWS secured object from the specified JSON object
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The JWS secured object.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        JWS secured object.
	 */
	public static JWSObjectJSON parse(final Map<String, Object> jsonObject)
		throws ParseException {
		
		// Payload always present
		Base64URL payloadB64URL = JSONObjectUtils.getBase64URL(jsonObject, "payload");
		
		if (payloadB64URL == null) {
			throw new ParseException("Missing payload", 0);
		}
		
		Payload payload = new Payload(payloadB64URL);
		
		// Signature present at top-level in flattened JSON
		Base64URL topLevelSignatureB64 = JSONObjectUtils.getBase64URL(jsonObject, "signature");
		
		boolean flattened = topLevelSignatureB64 != null;
		
		List<Signature> signatureList = new LinkedList<>();
		
		if (flattened) {
			
			JWSHeader jwsHeader = parseJWSHeader(jsonObject);
			
			UnprotectedHeader unprotectedHeader = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(jsonObject, "header"));
			
			// https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2
			// "The "signatures" member MUST NOT be present when using this syntax."
			if (jsonObject.get("signatures") != null) {
				throw new ParseException("The \"signatures\" member must not be present in flattened JWS JSON serialization", 0);
			}
			
			try {
				HeaderValidation.ensureDisjoint(jwsHeader, unprotectedHeader);
			} catch (IllegalHeaderException e) {
				throw new ParseException(e.getMessage(), 0);
			}
			
			signatureList.add(new Signature(payload, jwsHeader, unprotectedHeader, topLevelSignatureB64));
			
		} else {
			Map<String, Object>[] signatures = JSONObjectUtils.getJSONObjectArray(jsonObject, "signatures");
			if (signatures == null || signatures.length == 0) {
				throw new ParseException("The \"signatures\" member must be present in general JSON Serialization", 0);
			}
			
			for (Map<String, Object> signatureJSONObject: signatures) {
				
				JWSHeader jwsHeader = parseJWSHeader(signatureJSONObject);
				
				UnprotectedHeader unprotectedHeader = UnprotectedHeader.parse(JSONObjectUtils.getJSONObject(signatureJSONObject, "header"));
				
				try {
					HeaderValidation.ensureDisjoint(jwsHeader, unprotectedHeader);
				} catch (IllegalHeaderException e) {
					throw new ParseException(e.getMessage(), 0);
				}
				
				Base64URL signatureB64 = JSONObjectUtils.getBase64URL(signatureJSONObject, "signature");
				
				if (signatureB64 == null) {
					throw new ParseException("Missing \"signature\" member", 0);
				}
				
				signatureList.add(new Signature(payload, jwsHeader, unprotectedHeader, signatureB64));
			}
		}
		
		return new JWSObjectJSON(payload, signatureList);
	}
	
	
	/**
	 * Parses a JWS secured object from the specified JSON object string.
	 *
	 * @param json The JSON object string to parse. Must not be
	 *             {@code null}.
	 *
	 * @return The JWS secured object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a JWS
	 *                        secured object.
	 */
	public static JWSObjectJSON parse(final String json)
		throws ParseException {
		
		return parse(JSONObjectUtils.parse(json));
	}
}
