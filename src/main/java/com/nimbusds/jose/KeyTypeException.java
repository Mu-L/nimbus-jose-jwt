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


import java.security.Key;
import java.util.Arrays;


/**
 * Key type exception.
 *
 * @author Vladimir Dzhuvinov
 * @author stisve
 * @version 2020-03-03
 */
public class KeyTypeException extends KeyException {


	/**
	 * Creates a new key type exception.
	 *
	 * @param expectedKeyClass The expected key class. Should not be
	 *                         {@code null}.
	 */
	public KeyTypeException(final Class<? extends Key> expectedKeyClass) {

		super("Invalid key: Must be an instance of " + expectedKeyClass);
	}

	/**
	 * Creates a new key type exception.
	 *
	 * @param expectedKeyInterface The expected key interfaces. Should not
	 *                             be {@code null}.
	 * @param additionalInterfaces Additional interfaces the key is required to implement.
	 */
	public KeyTypeException(final Class<? extends Key> expectedKeyInterface, final Class<?> ... additionalInterfaces) {

		super("Invalid key: Must be an instance of " + expectedKeyInterface
				+ " and implement all of the following interfaces " + Arrays.toString(additionalInterfaces));
	}
}
