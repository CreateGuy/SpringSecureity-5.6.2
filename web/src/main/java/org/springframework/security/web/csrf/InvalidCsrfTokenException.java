/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.csrf;

import javax.servlet.http.HttpServletRequest;

/**
 * 当 {@link CsrfToken} 不匹配的情况，抛出的异常
 */
@SuppressWarnings("serial")
public class InvalidCsrfTokenException extends CsrfException {

	/**
	 * @param expectedAccessToken
	 * @param actualAccessToken
	 */
	public InvalidCsrfTokenException(CsrfToken expectedAccessToken, String actualAccessToken) {
		super("Invalid CSRF Token '" + actualAccessToken + "' was found on the request parameter '"
				+ expectedAccessToken.getParameterName() + "' or header '" + expectedAccessToken.getHeaderName()
				+ "'.");
	}

}
