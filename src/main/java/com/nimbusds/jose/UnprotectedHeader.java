package com.nimbusds.jose;


import java.text.ParseException;
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.util.JSONObjectUtils;


/**
 * Unprotected JSON Web Signature (JWS) or JSON Web Encryption (JWE) header in
 * a JSON serialisation. This class is immutable.
 *
 * @author Alexander Martynov
 * @author Vladimir Dzhuvinov
 * @version 2021-09-30
 */
@Immutable
public final class UnprotectedHeader {
	
	
	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;

	
	static {
		Set<String> p = new HashSet<>();
		p.add(HeaderParameterNames.KEY_ID);
		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}
	
	
	/**
	 * Gets the registered parameter names for unprotected headers.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredParameterNames() {
		
		return REGISTERED_PARAMETER_NAMES;
	}
	
	
	/**
	 * The header parameters.
	 */
	private final Map<String, Object> params;
	
	
	/**
	 * Create a new unprotected header.
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
	 * Gets a custom (non-registered) parameter.
	 *
	 * @param name The name of the custom parameter. Must not be
	 *             {@code null}.
	 *
	 * @return The custom parameter, {@code null} if not specified.
	 */
	public Object getCustomParam(final String name) {
		
		return params.get(name);
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
		
		String kid = JSONObjectUtils.getString(jsonObject, HeaderParameterNames.KEY_ID);
		Builder header = new Builder(kid);
		
		for (final String name : jsonObject.keySet()) {
			if (!HeaderParameterNames.KEY_ID.equals(name)) {
				header = header.customParam(name, jsonObject.get(name));
			}
		}
		
		return header.build();
	}
	
	
	/**
	 * Builder for constructing an unprotected JWS or JWE header.
	 */
	public static class Builder {
		
		
		private final Map<String, Object> params = JSONObjectUtils.newJSONObject();
		
		
		/**
		 * Creates a new unprotected header builder with the specified
		 * key ID ({@code kid}).
		 *
		 * @param kid The key ID. Must be not {@code null}.
		 */
		public Builder(final String kid) {
			Objects.requireNonNull(kid, "The \"kid\" must not be null");
			params.put(HeaderParameterNames.KEY_ID, kid);
		}
		
		
		/**
		 * Sets a custom (non-registered) parameter.
		 *
		 * @param name  The name of the custom parameter. Must not
		 *              match a registered parameter name and must not
		 *              be {@code null}.
		 * @param value The value of the custom parameter, should map
		 *              to a valid JSON entity, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 *
		 * @throws IllegalArgumentException If the specified parameter
		 *                                  name matches a registered
		 *                                  parameter name.
		 */
		public Builder customParam(final String name, final Object value) {
			
			if (getRegisteredParameterNames().contains(name)) {
				throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
			}
			params.put(name, value);
			return this;
		}
		
		
		/**
		 * Build a new unprotected header.
		 *
		 * @return The unprotected header.
		 */
		public UnprotectedHeader build() {
			return new UnprotectedHeader(params);
		}
	}
}
