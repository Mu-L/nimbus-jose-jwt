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

package com.nimbusds.jose;

import java.util.Map;

/**
 * Provides JSON serialization of the JOSE Object.
 *
 * @author Alexander Martynov
 * @version 2021-08-17
 */
public interface JSONSerializable {

    /**
     * Returns a JSON object representation of the JOSE Object.
     *
     * @throws IllegalStateException If the JOSE object is not in a state
     *                               that permits serialisation.
     * @return The JSON object.
     */
    Map<String, Object> toJSONObject(boolean flattened);
}
