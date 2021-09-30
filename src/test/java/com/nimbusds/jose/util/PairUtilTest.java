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


import java.util.Arrays;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import junit.framework.TestCase;

/**
 * Tests JWS JSON Serialization object methods.
 *
 * @author Alexander Martynov
 * @version 2021-08-24
 */
public class PairUtilTest extends TestCase {


    public void test_PairCreation() {
        String expectedLeft = "True";
        Integer expectedRight = 42;

        Pair<String, Integer> pair = Pair.of("True", 42);

        assertEquals(expectedLeft, pair.getLeft());
        assertEquals(expectedRight, pair.getRight());
    }

}
