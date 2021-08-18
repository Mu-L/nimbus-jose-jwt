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


import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.Base64URL;

import java.util.List;


public interface JWEDecrypterMulti<Key extends JWK> extends JWEProvider {

	byte[] decrypt(final JWEHeader header,
                   final List<Recipient> recipients,
                   final Base64URL iv,
                   final Base64URL cipherText,
                   final Base64URL authTag)
		throws JOSEException;

	byte[] decrypt(final JWEHeader header,
				   final Key key,
				   final Recipient recipient,
				   final Base64URL iv,
				   final Base64URL cipherText,
				   final Base64URL authTag)
			throws JOSEException;
}
