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

package com.nimbusds.jose;


/**
 * Action required for JWS completion. Can be used to signal a user
 * authentication requirement in Android to unlock a private signing key
 * created with {@code setUserAuthenticationRequired(true)}.
 */
public class ActionRequiredForJWSCompletionException extends JOSEException {
	
	
	private final JWSSignerOption option;
	
	
	private final CompletableJWSObjectSigning completableSigning;
	
	
	/**
	 * Creates a new action required for JWS completion exception.
	 *
	 * @param message            The exception message.
	 * @param option             The JWS signer option that triggered the
	 *                           exception.
	 * @param completableSigning To complete the JWS object signing after
	 *                           the required action.
	 */
	public ActionRequiredForJWSCompletionException(final String message,
						       final JWSSignerOption option,
						       final CompletableJWSObjectSigning completableSigning) {
		super(message);
		if (option == null) {
			throw new IllegalArgumentException("The triggering option must not be null");
		}
		this.option = option;
		
		if (completableSigning == null) {
			throw new IllegalArgumentException("The completable signing must not be null");
		}
		this.completableSigning = completableSigning;
	}
	
	
	/**
	 * Returns the JWS signer option that triggered this exception.
	 *
	 * @return The JWS signer option.
	 */
	public JWSSignerOption getTriggeringOption() {
		return option;
	}
	
	
	/**
	 * Returns an interface to complete the JWS object signing after the
	 * required action is performed.
	 *
	 * @return The completable JWS object signing.
	 */
	public CompletableJWSObjectSigning getCompletableJWSObjectSigning() {
		return completableSigning;
	}
}
