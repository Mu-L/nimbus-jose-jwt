package com.nimbusds.jose;


import java.text.ParseException;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * JSON Web Signature (JWS) or JSON Web Encryption (JWE) unprotected header
 * (in a JSON serialisation). This class is immutable.
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-10-05
 */
@Immutable
public final class UnprotectedHeader {
	
	
	/**
	 * The header parameters.
	 */
	private final Map<String, Object> params;
	
	
	/**
	 * Creates a new unprotected header.
	 *
	 * @param params The header parameters. Must not be {@code null}.
	 */
	private UnprotectedHeader(final Map<String, Object> params) {
		Objects.requireNonNull(params);
		this.params = params;
	}
	
	
	/**
	 * Gets the key ID ({@code kid}) parameter.
	 *
	 * @return The key ID parameter, {@code null} if not specified.
	 */
	public String getKeyID() {
		
		return (String) params.get(HeaderParameterNames.KEY_ID);
	}
	
	
	/**
	 * Gets a parameter.
	 *
	 * @param name The name of the parameter. Must not be {@code null}.
	 *
	 * @return The parameter, {@code null} if not specified.
	 */
	public Object getParam(final String name) {
		
		return params.get(name);
	}
	
	
	/**
	 * Gets the names of the included parameters in this unprotected
	 * header.
	 *
	 * @return The included parameters.
	 */
	public Set<String> getIncludedParams() {
		
		return params.keySet();
	}
	
	
	/**
	 * Returns a JSON object representation of this unprotected header.
	 *
	 * @return The JSON object, empty if no parameters are specified.
	 */
	public Map<String, Object> toJSONObject() {
		
		Map<String, Object> o = JSONObjectUtils.newJSONObject();
		o.putAll(params);
		return o;
	}
	
	
	/**
	 * Parses an unprotected header from the specified JSON object.
	 *
	 * @param jsonObject The JSON object, {@code null} if not specified.
	 *
	 * @return The unprotected header or {@code null}.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to a
	 *                        valid unprotected header.
	 */
	public static UnprotectedHeader parse(final Map<String, Object> jsonObject)
		throws ParseException {
		
		if (jsonObject == null) {
			return null;
		}
		
		Builder header = new Builder();
		
		for (final String name : jsonObject.keySet()) {
			header = header.param(name, jsonObject.get(name));
		}
		
		return header.build();
	}
	
	
	/**
	 * Builder for constructing an unprotected JWS or JWE header.
	 */
	public static class Builder {
		
		
		private final Map<String, Object> params = JSONObjectUtils.newJSONObject();
		
		
		/**
		 * Creates a new unprotected header builder.
		 */
		public Builder() {
		
		}
		
		
		/**
		 * Sets the key ID ({@code kid}) parameter.
		 *
		 * @param kid The key ID parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String kid) {
			params.put(HeaderParameterNames.KEY_ID, kid);
			return this;
		}
		
		
		/**
		 * Sets a parameter.
		 *
		 * @param name  The name of the parameter. Must  not be
		 *              {@code null}.
		 * @param value The value of the parameter, should map to a
		 *              valid JSON entity, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 */
		public Builder param(final String name, final Object value) {
			params.put(name, value);
			return this;
		}
		
		
		/**
		 * Builds a new unprotected header.
		 *
		 * @return The unprotected header.
		 */
		public UnprotectedHeader build() {
			return new UnprotectedHeader(params);
		}
	}
}
