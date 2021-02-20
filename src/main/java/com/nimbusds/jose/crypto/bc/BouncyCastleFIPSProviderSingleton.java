/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd.
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

package com.nimbusds.jose.crypto.bc;


import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;


/**
 * BouncyCastle FIPS JCA provider singleton, intended to prevent memory leaks
 * by ensuring a single instance is loaded at all times. Application code that
 * needs a BouncyCastle FIPS JCA provider should use the {@link #getInstance()}
 * method to obtain an instance.
 *
 * <p>Requires the following optional dependency:
 *
 * <pre>
 * &lt;dependency&gt;
 *     &lt;groupId&gt;org.bouncycastle&lt;/groupId&gt;
 *     &lt;artifactId&gt;bc-fips&lt;/artifactId&gt;
 *     &lt;version&gt;[1.0.2,2.0.0)&lt;/version&gt;
 *     &lt;optional&gt;true&lt;/optional&gt;
 * &lt;/dependency&gt;
 * </pre>
 *
 * <p><strong>Important:</strong> The plain BouncyCastle JCA provider
 * dependency must not be present to prevent class conflicts!
 *
 * @author Vladimir Dzhuvinov
 */
public final class BouncyCastleFIPSProviderSingleton {


	/**
	 * The BouncyCastle FIPS provider, lazily instantiated.
	 */
	private static BouncyCastleFipsProvider bouncyCastleFIPSProvider;


	/**
	 * Prevents external instantiation.
	 */
	private BouncyCastleFIPSProviderSingleton() { }


	/**
	 * Returns a BouncyCastle FIPS JCA provider instance.
	 *
	 * @return The BouncyCastle FIPS JCA provider instance.
	 */
	public static BouncyCastleFipsProvider getInstance() {
		
		if (bouncyCastleFIPSProvider == null) {
			bouncyCastleFIPSProvider = new BouncyCastleFipsProvider();
		}
		return bouncyCastleFIPSProvider;
	}
}
