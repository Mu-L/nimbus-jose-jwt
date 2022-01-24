/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.jwk.source;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.proc.JWKSecurityContext;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class JWKSecurityContextJWKSetTest {
	private static final JWKSelector SELECT_ALL = new JWKSelector(new JWKMatcher.Builder().build());
	private static final JWKSelector SELECT_NONE = new JWKSelector(new JWKMatcher.Builder().maxKeySize(1).build());

	private JWK jwk;
	private final JWKSecurityContextJWKSet jwkSource = new JWKSecurityContextJWKSet();

	@Before
	public void lookupJwk() throws Exception {
		String json = "{\"kty\":\"OKP\",\"crv\":\"X448\",\"kid\":\"Dave\",\"x\":\"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk\"}";
		this.jwk = JWK.parse(json);
	}

	@Test
	public void testGetWithEmptyContext() throws Exception {
		List<JWK> keys =
				this.jwkSource.get(SELECT_ALL, new JWKSecurityContext(Collections.<JWK>emptyList()));

		Assert.assertNotNull(keys);
		Assert.assertEquals(0, keys.size());
	}

	@Test
	public void testGetWithPopulatedContext() throws Exception {
		List<JWK> keys =
				this.jwkSource.get(SELECT_ALL, new JWKSecurityContext(Arrays.asList(this.jwk)));

		Assert.assertNotNull(keys);
		Assert.assertEquals(1, keys.size());
	}

	@Test
	public void testGetWithSelectiveSelector() throws Exception {
		List<JWK> keys =
				this.jwkSource.get(SELECT_NONE, new JWKSecurityContext(Arrays.asList(this.jwk)));

		Assert.assertNotNull(keys);
		Assert.assertEquals(0, keys.size());
	}


	@Test(expected = IllegalArgumentException.class)
	public void testGetWithNullContext() throws Exception {
		this.jwkSource.get(SELECT_ALL, null);
	}
}
