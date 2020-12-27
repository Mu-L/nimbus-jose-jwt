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

package com.nimbusds.jose.crypto.impl;


import junit.framework.TestCase;
import org.junit.Assert;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64URL;


public class ECDSATest extends TestCase {


	// https://tools.ietf.org/html/rfc7515#appendix-A.3
	public void testES256_encodingRoundTrip() throws JOSEException {
		
		Base64URL b64sig = new Base64URL("DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q");
		
		byte[] jwsSignature = b64sig.decode();
		
		byte[] derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);
		
		Assert.assertArrayEquals(jwsSignature, ECDSA.transcodeSignatureToConcat(derSignature, 64));
	}
	
	
	// https://tools.ietf.org/html/rfc7520#section-4.3
	public void testES512_encodingRoundTrip() throws JOSEException {
		
		Base64URL b64sig = new Base64URL(
			"AE_R_YZCChjn4791jSQCrdPZCNYqHXCTZH0-JZGYNlaAjP2kqaluUIIUnC9qvb" +
			"u9Plon7KRTzoNEuT4Va2cmL1eJAQy3mtPBu_u_sDDyYjnAMDxXPn7XrT0lw-kv" +
			"AD890jl8e2puQens_IEKBpHABlsbEPX6sFY8OcGDqoRuBomu9xQ2");
		
		byte[] jwsSignature = b64sig.decode();
		
		byte[] derSignature = ECDSA.transcodeSignatureToDER(jwsSignature);
		
		Assert.assertArrayEquals(jwsSignature, ECDSA.transcodeSignatureToConcat(derSignature, 132));
	}
}
