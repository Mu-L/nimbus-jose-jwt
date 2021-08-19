/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2021, Connect2id Ltd and contributors.
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

package com.nimbusds.jose.crypto.impl;


import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Container;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;


/**
 * Tests the authenticated XC20P encryption and decryption methods. Uses test
 * vectors from draft-irtf-cfrg-xchacha-03, appendix A.
 *
 * @author Alexander Martynov
 * @version 2021-08-04
 */
public class XC20PTest extends TestCase {

    private static byte[] fromHex(String hex) {
        byte[] result = new byte[hex.length() / 2];
        for (int i=0; i<result.length; i++) {
            result[i] = (byte) Integer.parseInt(hex.substring(2*i, 2*i + 2), 16);
        }
        return result;
    }

    private static class TestVector {
        public byte[] iv;
        public byte[] key;
        public byte[] tag;
        public byte[] aad;
        public byte[] plaintext;
        public byte[] ciphertext;

        public TestVector(byte[] iv,
                          byte[] key,
                          byte[] aad,
                          byte[] tag,
                          byte[] plaintext,
                          byte[] ciphertext) {
            this.iv = iv;
            this.key = key;
            this.tag = tag;
            this.aad = aad;
            this.plaintext = plaintext;
            this.ciphertext = ciphertext;
        }
    }

    public void testEncryptDecrypt() throws JOSEException {
        SecureRandom secureRandom = new SecureRandom();
        String plainText = "Hello, world!";


        // secret key
        SecretKey key = ContentCryptoProvider.generateCEK(EncryptionMethod.XC20P, secureRandom);

        // aad
        byte[] aad = new byte[128];
        secureRandom.nextBytes(aad);

        // IV
        Container<byte[]> ivContainer = new Container<>(null);

        AuthenticatedCipherText authenticatedCipherText = XC20P.encryptAuthenticated(
                key,
                ivContainer,
                plainText.getBytes(StandardCharsets.UTF_8),
                aad
        );

        byte[] decrypted = XC20P.decryptAuthenticated(
                key,
                ivContainer.get(),
                authenticatedCipherText.getCipherText(),
                aad,
                authenticatedCipherText.getAuthenticationTag()
        );

        String clearText = new String(decrypted, StandardCharsets.UTF_8);
        assertEquals(plainText, clearText);
    }

    /**
     * see https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03#appendix-A.3.1
     */
    public void test_TestVector() throws JOSEException {
        TestVector tv = new TestVector(
                fromHex("404142434445464748494a4b4c4d4e4f5051525354555657"),
                fromHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"),
                fromHex("50515253c0c1c2c3c4c5c6c7"),
                fromHex("c0875924c1c7987947deafd8780acf49"),
                fromHex("4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
                        "73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
                        "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
                        "637265656e20776f756c642062652069742e"),
                fromHex("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb" +
                        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452" +
                        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9" +
                        "21f9664c97637da9768812f615c68b13b52e"));

        SecretKey key = new SecretKeySpec(tv.key, "AES");

        byte[] decrypted = XC20P.decryptAuthenticated(
                key,
                tv.iv,
                tv.ciphertext,
                tv.aad,
                tv.tag
        );

        assertArrayEquals(tv.plaintext, decrypted);
    }
}
