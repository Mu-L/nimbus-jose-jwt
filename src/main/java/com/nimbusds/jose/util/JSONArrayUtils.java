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
package com.nimbusds.jose.util;

import java.util.ArrayList;
import java.util.List;

/**
 * JSON Array helper methods for parsing and typed retrieval of member values.
 *
 * @author Toma Velev
 * @version 2020-06-22
 */
public class JSONArrayUtils {

	/**
	 * Creates a new Array with the purpose of holding JSON Objects
	 * @return new empty Array
	 */
	public static List<Object> newJSONArray() {
		return new ArrayList<Object>();
	}

}
