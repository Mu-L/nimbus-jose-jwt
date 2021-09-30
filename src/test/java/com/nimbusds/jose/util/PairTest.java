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

package com.nimbusds.jose.util;


import junit.framework.TestCase;


/**
 * @author Alexander Martynov
 * @version 2021-09-30
 */
public class PairTest extends TestCase {
	
	
	public void test_PairCreation() {
		
		String expectedLeft = "True";
		Integer expectedRight = 42;
		
		Pair<String, Integer> pair = Pair.of("True", 42);
		
		assertEquals(expectedLeft, pair.getLeft());
		assertEquals(expectedRight, pair.getRight());
	}
	
	
	public void test_PairCreation_NullValues() {
		
		Pair<Object,Object> pair = Pair.of(null, null);
		
		assertNull(pair.getLeft());
		assertNull(pair.getRight());
	}
}
