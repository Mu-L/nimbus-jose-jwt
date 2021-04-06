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

import com.nimbusds.jose.util.JSONStringUtils;

import net.jcip.annotations.Immutable;



/**
 * JOSE object type, represents the {@code typ} header parameter in unsecured,
 * JSON Web Signature (JWS) and JSON Web Encryption (JWE) objects. This class
 * is immutable.
 *
 * <p>Includes constants for the following standard types:
 *
 * <ul>
 *     <li>{@link #JOSE}
 *     <li>{@link #JOSE_JSON JOSE+JSON}
 *     <li>{@link #JWT}
 * </ul>
 *
 * <p>Additional types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @version 2021-04-06
 */
@Immutable
public final class JOSEObjectType implements  Serializable {


	private static final long serialVersionUID = 1L;


	/**
	 * Compact encoded JOSE object type.
	 */
	public static final JOSEObjectType JOSE = new JOSEObjectType("JOSE");


	/**
	 * JSON-encoded JOSE object type..
	 */
	public static final JOSEObjectType JOSE_JSON = new JOSEObjectType("JOSE+JSON");


	/**
	 * JSON Web Token (JWT) object type.
	 */
	public static final JOSEObjectType JWT = new JOSEObjectType("JWT");


	/**
	 * The object type.
	 */
	private final String type;


	/**
	 * Creates a new JOSE object type.
	 *
	 * @param type The object type. Must not be {@code null}.
	 */
	public JOSEObjectType(final String type) {

		if (type == null) {
			throw new IllegalArgumentException("The object type must not be null");
		}

		this.type = type;
	}


	/**
	 * Gets the JOSE object type.
	 *
	 * @return The JOSE object type.
	 */
	public String getType() {

		return type;
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public int hashCode() {

		return type.toLowerCase().hashCode();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object instanceof JOSEObjectType &&
			this.type.equalsIgnoreCase(((JOSEObjectType) object).type);
	}


	/**
	 * Returns the string representation of this JOSE object type.
	 *
	 * @see #getType
	 *
	 * @return The string representation.
	 */
	@Override
	public String toString() {

		return type;
	}


	/**
	 * Returns the JSON string representation of this JOSE object type.
	 * 
	 * @return The JSON string representation.
	 */
	public String toJSONString() {
		return JSONStringUtils.toJSONString(type);
	}
}
