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

package com.nimbusds.jose;


import java.io.Serializable;
import java.text.ParseException;
import java.util.Map;

import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * The base abstract class for JSON Web Signature (JWS) secured and JSON Web
 * Encryption (JWE) secured objects serialisable to JSON.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-10-05
 */
public abstract class JOSEObjectJSON implements Serializable {
	
	
	private static final long serialVersionUID = 1L;


	/**
	 * The MIME type of JOSE objects serialised to JSON:
	 * {@code application/jose+json; charset=UTF-8}
	 */
	public static final String MIME_TYPE_JOSE_JSON = "application/jose+json; charset=UTF-8";


	/**
	 * The payload (message), {@code null} if not specified.
	 */
	private Payload payload;


	/**
	 * Creates a new JOSE object with the specified payload.
	 *
	 * @param payload The payload, {@code null} if not available (e.g. for
	 *                an encrypted JWE object).
	 */
	protected JOSEObjectJSON(final Payload payload) {

		this.payload = payload;
	}


	/**
	 * Sets the payload of this JOSE object.
	 *
	 * @param payload The payload, {@code null} if not available (e.g. for 
	 *                an encrypted JWE object).
	 */
	protected void setPayload(final Payload payload) {

		this.payload = payload;
	}


	/**
	 * Returns the payload of this JOSE object.
	 *
	 * @return The payload, {@code null} if not available (for an encrypted
	 *         JWE object that hasn't been decrypted).
	 */
	public Payload getPayload() {

		return payload;
	}
	
	
	/**
	 * Returns a general JSON object representation of this JOSE secured
	 * object.
	 *
	 * <p>See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1">JWS
	 * general serialisation</a> or
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1">JWE
	 * general serialisation</a>.
	 *
	 * @return The JSON object.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state
	 *                               that permits serialisation.
	 */
	abstract Map<String, Object> toGeneralJSONObject();
	
	
	/**
	 * Returns a flattened JSON object representation of this JOSE secured
	 * object. There must be exactly one JWS signature or JWE recipient for
	 * a flattened JSON serialisation.
	 *
	 * <p>See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2">JWS
	 * flattened serialisation</a> or
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.2">JWE
	 * flattened serialisation</a>.
	 *
	 * @return The JSON object.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state
	 *                               that permits serialisation or there
	 *                               is more than one JWS signature or JWE
	 *                               recipient.
	 */
	abstract Map<String, Object> toFlattenedJSONObject();
	
	
	/**
	 * Serialises this JOSE object to a general JOSE object string.
	 *
	 * <p>See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.1">JWS
	 * general serialisation</a> or
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.1">JWE
	 * general serialisation</a>.
	 *
	 * @return The JSON object string.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state
	 *                               that permits serialisation.
	 */
	public abstract String serializeGeneral();
	
	
	/**
	 * Serialises this JOSE object to a flattened JSON object string. There
	 * must be exactly one JWS signature or JWE recipient for a flattened
	 * JSON serialisation.
	 *
	 * <p>See
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.2.2">JWS
	 * flattened serialisation</a> or
	 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.2.2">JWE
	 * flattened serialisation</a>.
	 *
	 * @return The JSON object string.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state
	 *                               that permits serialisation or there
	 *                               is more than one JWS signature or JWE
	 *                               recipient.
	 */
	public abstract String serializeFlattened();
	
	
	/**
	 * Parses a JOSE secured object from the specified JSON object
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The corresponding {@link JWSObjectJSON} or
	 *         {@link JWEObjectJSON}.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        valid JWS or JWE secured object.
	 */
	public static JOSEObjectJSON parse(final Map<String, Object> jsonObject)
		throws ParseException {
		
		if (jsonObject.containsKey("signature") || jsonObject.containsKey("signatures")) {
			return JWSObjectJSON.parse(jsonObject);
		} else if (jsonObject.containsKey("ciphertext")) {
			return null; // TODO
		} else {
			throw new ParseException("Invalid JOSE object", 0);
		}
	}


	/**
	 * Parses a JOSE secured object from the specified JSON string.
	 *
	 * @param json The JSON string to parse. Must not be {@code null}.
	 *
	 * @return The corresponding {@link JWSObjectJSON} or
	 *         {@link JWEObjectJSON}.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        JWS or JWE secured object.
	 */
	public static JOSEObjectJSON parse(final String json)
		throws ParseException {

		return parse(JSONObjectUtils.parse(json));
	}
}
