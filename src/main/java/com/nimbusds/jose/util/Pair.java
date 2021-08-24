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
import net.jcip.annotations.ThreadSafe;

/**
 * A pair consisting of two elements.
 *
 * This class Immutable and ThreadSafe.
 *
 * @param <L> the left element type
 * @param <R> the right element type
 *
 * @author Alexander Martynov
 * @version 2021-08-24
 */
@Immutable
@ThreadSafe
public class Pair<L, R> {
    private L left;
    private R right;

    protected Pair(L left, R right) {
        this.left = left;
        this.right = right;
    }

    public static <L, R> Pair<L, R> of(L left, R right) {
        return new Pair<>(left, right);
    }

    /**
     * Gets the left element from this pair.
     *
     * @return the left element
     */
    public L getLeft() {
        return left;
    }

    /**
     * Gets the right element from this pair.
     * @return the right element
     */
    public R getRight() {
        return right;
    }
}
