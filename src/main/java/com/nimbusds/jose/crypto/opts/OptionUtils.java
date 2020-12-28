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

package com.nimbusds.jose.crypto.opts;


import java.util.Set;

import com.nimbusds.jose.JWSSignerOption;


/**
 * Utilities for processing JOSE options.
 */
public class OptionUtils {
	
	
	/**
	 * Returns {@code true} if the specified set of options contains an
	 * instance of a class implementing {@link JWSSignerOption}.
	 *
	 * @param opts   The options set, may be {@code null}.
	 * @param tClass The class. Must not be {@code null}.
	 *
	 * @return {@code true} if an option is present, else {@code false}.
	 */
	public static <T extends JWSSignerOption> boolean optionIsPresent(final Set<JWSSignerOption> opts, final Class<T> tClass) {
		
		if (opts == null || opts.isEmpty()) {
			return false;
		}
		
		for (JWSSignerOption o: opts) {
			
			if (o.getClass().isAssignableFrom(tClass)) {
				return true;
			}
		}
		
		return false;
	}
}
