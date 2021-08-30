/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.proc;


import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEObjectType;


/**
 * Default JOSE header "typ" (type) parameter verifier.
 *
 * <p>Example JWS header with a "typ" (type) parameter set to "at+jwt":
 *
 * <pre>
 * {
 *   "alg" : "ES256",
 *   "typ" : "at+jwt",
 *   "kid" : "123"
 * }
 * </pre>
 *
 * <p>To create a verifier which allows the "typ" to be omitted or set to
 * "JWT":
 *
 * <pre>
 * JOSEObjectVerifier verifier = new DefaultJOSEObjectTypeVerifier(JOSEObjectType.JWT, null);
 * </pre>
 *
 * <p>To create a verifier which allows a "typ" of "at+jwt":
 *
 * <pre>
 * JOSEObjectVerifier verifier = new DefaultJOSEObjectTypeVerifier(new JOSEObjectType("at+jwt")));
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version 2019-10-15
 * @since 8.0
 */
@Immutable
public class DefaultJOSEObjectTypeVerifier <C extends SecurityContext> implements JOSEObjectTypeVerifier<C> {
	
	
	/**
	 * The allowed types.
	 */
	private final Set<JOSEObjectType> allowedTypes;
	
	
	/**
	 * The standard header "typ" (type) parameter verifier for JWS, JWE and
	 * plain (unsecured) JOSE objects (other than JWT). See RFC 7515,
	 * section 4.1.9 and RFC 7516, section 4.1.11.
	 */
	public static final DefaultJOSEObjectTypeVerifier JOSE = new DefaultJOSEObjectTypeVerifier(JOSEObjectType.JOSE, null);
	
	/**
	 * The standard header "typ" (type) parameter verifier for signed,
	 * encrypted and plain (unsecured) JWTs. See RFC 7519, section 5.1.
	 */
	public static final DefaultJOSEObjectTypeVerifier JWT = new DefaultJOSEObjectTypeVerifier(JOSEObjectType.JWT, null);
	
	
	/**
	 * Creates a new JOSE object type verifier which allows the type to be
	 * omitted or {@code null}.
	 */
	public DefaultJOSEObjectTypeVerifier() {
		
		this.allowedTypes = Collections.singleton(null);
	}
	
	
	/**
	 * Creates a new JOSE object type verifier allowing the specified
	 * types.
	 *
	 * @param allowedTypes The allowed types, if a {@code null} is included
	 *                     the type parameter may be omitted or
	 *                     {@code null}. The set must not be {@code null}
	 *                     or empty.
	 */
	public DefaultJOSEObjectTypeVerifier(final Set<JOSEObjectType> allowedTypes) {
		if (allowedTypes == null || allowedTypes.isEmpty()) {
			throw new IllegalArgumentException("The allowed types must not be null or empty");
		}
		this.allowedTypes = allowedTypes;
	}
	
	
	/**
	 * Creates a new JOSE object type verifier allowing the specified
	 * types.
	 *
	 * @param allowedTypes The allowed types, if a {@code null} is included
	 *                     the type parameter may be omitted or
	 *                     {@code null}. The array must not be {@code null}
	 *                     or empty.
	 */
	public DefaultJOSEObjectTypeVerifier(final JOSEObjectType ... allowedTypes) {
		if (allowedTypes == null || allowedTypes.length == 0) {
			throw new IllegalArgumentException("The allowed types must not be null or empty");
		}
		this.allowedTypes = new HashSet<>(Arrays.asList(allowedTypes));
	}
	
	
	/**
	 * Returns the allowed JOSE object types.
	 *
	 * @return The allowed JOSE object types, if a {@code null} is included
	 *         the type parameter may be omitted or {@code null}.
	 */
	public Set<JOSEObjectType> getAllowedTypes() {
		return allowedTypes;
	}
	
	
	@Override
	public void verify(final JOSEObjectType type, final C context)
		throws BadJOSEException {
	
		if (type == null && ! allowedTypes.contains(null)) {
			throw new BadJOSEException("Required JOSE header typ (type) parameter is missing");
		}
		
		if (! allowedTypes.contains(type)) {
			throw new BadJOSEException("JOSE header typ (type) " + type + " not allowed");
		}
	}
}
