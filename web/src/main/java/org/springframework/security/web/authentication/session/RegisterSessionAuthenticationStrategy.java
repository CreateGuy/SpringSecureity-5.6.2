/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.util.Assert;

/**
 * 在身份认证成功后，用于向SessionInformation注册中心 注册一个对应的SessionInformation
 */
public class RegisterSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

	/**
	 * SessionInformation注册中心
	 */
	private final SessionRegistry sessionRegistry;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 * authenticated session is changed.
	 */
	public RegisterSessionAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 * 为当前会话注册一个新的SessionInformation
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		this.sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());
	}

}
