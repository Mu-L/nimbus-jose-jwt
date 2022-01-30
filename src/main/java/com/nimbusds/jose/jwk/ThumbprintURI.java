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

package com.nimbusds.jose.jwk;


import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Objects;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;


/**
 * JSON Web Key (JWK) thumbprint URI.
 *
 * <p>See draft-ietf-oauth-jwk-thumbprint-uri
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-01-30
 */
@Immutable
public class ThumbprintURI {
	
	
	/**
	 * The URI prefix of JWK thumbprints.
	 */
	public static final String PREFIX = "urn:ietf:params:oauth:jwk-thumbprint:";
	
	
	/**
	 * The thumbprint value;
	 */
	private final Base64URL thumbprint;
	
	
	/**
	 * Creates a new JWK thumbprint URI.
	 *
	 * @param thumbprint the thumbprint value. Must not be {@code null}.
	 */
	public ThumbprintURI(final Base64URL thumbprint) {
		if (thumbprint == null) {
			throw new IllegalArgumentException("The thumbprint must not be null");
		}
		this.thumbprint = thumbprint;
	}
	
	
	/**
	 * Returns the underlying thumbprint value.
	 *
	 * @return The thumbprint value.
	 */
	public Base64URL getThumbprint() {
		
		return thumbprint;
	}
	
	
	/**
	 * Returns the {@link URI} representation.
	 *
	 * @return The {@link URI} representation.
	 */
	public URI toURI() {
		
		return URI.create(PREFIX + thumbprint);
	}
	
	
	@Override
	public String toString() {
		
		return PREFIX + thumbprint;
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof ThumbprintURI)) return false;
		ThumbprintURI that = (ThumbprintURI) o;
		return getThumbprint().equals(that.getThumbprint());
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getThumbprint());
	}
	
	
	/**
	 * Computes the SHA-256 JWK thumbprint URI for the specified JWK.
	 *
	 * @param jwk The JWK. Must not be {@code null}.
	 *
	 * @return The SHA-256 JWK thumbprint URI.
	 *
	 * @throws JOSEException If the SHA-256 hash algorithm is not
	 *                       supported.
	 */
	public static ThumbprintURI compute(final JWK jwk)
		throws JOSEException {
		
		return new ThumbprintURI(jwk.computeThumbprint());
	}
	
	
	/**
	 * Parses a JWK thumbprint URI from the specified URI.
	 *
	 * @param uri The URI. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint URI.
	 *
	 * @throws ParseException If the URI is illegal.
	 */
	public static ThumbprintURI parse(final URI uri)
		throws ParseException {
		
		String uriString = uri.toString();
		
		if (! uriString.startsWith(PREFIX)) {
			throw new ParseException("Illegal JWK thumbprint prefix", 0);
		}
		
		String thumbprintValue = uriString.substring(PREFIX.length());
		
		if (thumbprintValue.isEmpty()) {
			throw new ParseException("Illegal JWK thumbprint: Empty value", 0);
		}
		
		return new ThumbprintURI(new Base64URL(thumbprintValue));
	}
	
	
	/**
	 * Parses a JWK thumbprint URI from the specified URI string.
	 *
	 * @param s The URI string. Must not be {@code null}.
	 *
	 * @return The JWK thumbprint URI.
	 *
	 * @throws ParseException If the URI string is illegal.
	 */
	public static ThumbprintURI parse(final String s)
		throws ParseException {
		
		try {
			return parse(new URI(s));
		} catch (URISyntaxException e) {
			throw new ParseException(e.getMessage(), 0);
		}
	}
}
