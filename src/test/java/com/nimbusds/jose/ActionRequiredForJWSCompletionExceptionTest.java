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


import java.util.concurrent.atomic.AtomicBoolean;

import junit.framework.TestCase;

import com.nimbusds.jose.crypto.opts.UserAuthenticationRequired;
import com.nimbusds.jose.util.Base64URL;


public class ActionRequiredForJWSCompletionExceptionTest extends TestCase {


	public void testConstructor() throws JOSEException {
		
		String msg = "Require user authentication";
		
		final AtomicBoolean completeCalled = new AtomicBoolean(false);
		
		ActionRequiredForJWSCompletionException e = new ActionRequiredForJWSCompletionException(
			msg,
			UserAuthenticationRequired.getInstance(),
			new CompletableJWSObjectSigning() {
				@Override
				public Base64URL complete() throws JOSEException {
					completeCalled.set(true);
					return null;
				}
			}
		);
		
		assertEquals(msg, e.getMessage());
		assertEquals(UserAuthenticationRequired.getInstance(), e.getTriggeringOption());
		
		e.getCompletableJWSObjectSigning().complete();
		
		assertTrue(completeCalled.get());
	}
	
	
	public void testTriggeringOptionMustNotBeNull() {
		
		try {
			ActionRequiredForJWSCompletionException e = new ActionRequiredForJWSCompletionException(
				null,
				null,
				new CompletableJWSObjectSigning() {
					@Override
					public Base64URL complete() throws JOSEException {
						return null;
					}
				}
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The triggering option must not be null", e.getMessage());
		}
	}
	
	
	public void testCompletableMustNotBeNull() {
		
		try {
			ActionRequiredForJWSCompletionException e = new ActionRequiredForJWSCompletionException(
				null,
				UserAuthenticationRequired.getInstance(),
				null
			);
			fail();
		} catch (IllegalArgumentException e) {
			assertEquals("The completable signing must not be null", e.getMessage());
		}
	}
}
