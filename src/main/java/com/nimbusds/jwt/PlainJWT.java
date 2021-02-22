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

package com.nimbusds.jwt;


import java.text.ParseException;
import java.util.Map;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.PlainHeader;
import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.util.Base64URL;


/**
 * Unsecured (plain) JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-02-22
 */
@ThreadSafe
public class PlainJWT extends PlainObject implements JWT {


	private static final long serialVersionUID = 1L;

	/**
	 * The JWT claims set.
	 */
	private JWTClaimsSet claimsSet;


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with a default
	 * {@link com.nimbusds.jose.PlainHeader} and the specified claims 
	 * set.
	 *
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 */
	public PlainJWT(final JWTClaimsSet claimsSet) {

		super(claimsSet.toPayload());
		this.claimsSet = claimsSet;
	}


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with the
	 * specified header and claims set.
	 *
	 * @param header    The unsecured header. Must not be {@code null}.
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 */
	public PlainJWT(final PlainHeader header, final JWTClaimsSet claimsSet) {

		super(header, claimsSet.toPayload());
		this.claimsSet = claimsSet;
	}


	/**
	 * Creates a new unsecured (plain) JSON Web Token (JWT) with the
	 * specified Base64URL-encoded parts.
	 *
	 * @param firstPart  The first part, corresponding to the unsecured
	 *                   header. Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the claims set 
	 *                   (payload). Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public PlainJWT(final Base64URL firstPart, final Base64URL secondPart)
		throws ParseException {

		super(firstPart, secondPart);
	}


	@Override
	public JWTClaimsSet getJWTClaimsSet()
		throws ParseException {

		if (claimsSet != null) {

			return claimsSet;
		}

		Map<String, Object> json = getPayload().toJSONObject();

		if (json == null) {
			
			throw new ParseException("Payload of unsecured JOSE object is not a valid JSON object", 0);
		}

		claimsSet = JWTClaimsSet.parse(json);
		return claimsSet;
	}


	@Override
	protected void setPayload(Payload payload) {

		// setPayload() changes the result of getJWTClaimsSet().
		// set claimsSet = null and reparse payload again when called getJWTClaimsSet().
		claimsSet = null;
		super.setPayload(payload);
	}

	/**
	 * Parses an unsecured (plain) JSON Web Token (JWT) from the specified
	 * string in compact format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The unsecured JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        unsecured JWT.
	 */
	public static PlainJWT parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (! parts[2].toString().isEmpty()) {

			throw new ParseException("Unexpected third Base64URL part in the unsecured JWT object", 0);
		}

		return new PlainJWT(parts[0], parts[1]);
	}
}
