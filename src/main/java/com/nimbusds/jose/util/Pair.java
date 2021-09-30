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

package com.nimbusds.jose.util;


import net.jcip.annotations.Immutable;


/**
 * A pair of two objects.
 *
 * <p>This class is immutable.
 *
 * @param <L> the left object type.
 * @param <R> the right object type
 * @author Alexander Martynov
 * @version 2021-09-30
 */
@Immutable
public class Pair<L, R> {
	
	
	private final L left;
	
	
	private final R right;
	
	
	protected Pair(final L left, final R right) {
		this.left = left;
		this.right = right;
	}
	
	
	/**
	 * Creates a new pair of two objects.
	 *
	 * @param left  The left object, {@code null} if not specified.
	 * @param right The right object, {@code null} if not specified.
	 *
	 * @return The pair.
	 */
	public static <L, R> Pair<L, R> of(final L left, final R right) {
		return new Pair<>(left, right);
	}
	
	
	/**
	 * Returns the left object of this pair.
	 *
	 * @return The left object, {@code null} if not specified.
	 */
	public L getLeft() {
		return left;
	}
	
	
	/**
	 * Returns the right object of this pair.
	 *
	 * @return The right object, {@code null} if not specified.
	 */
	public R getRight() {
		return right;
	}
}
