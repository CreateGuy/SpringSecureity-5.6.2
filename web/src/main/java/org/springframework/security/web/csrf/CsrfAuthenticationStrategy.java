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
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

/**
 * 有关Csrf的HttpSession认证策略，是由于CsrfConfigurer注册的
 */
public final class CsrfAuthenticationStrategy implements SessionAuthenticationStrategy {

	private final Log logger = LogFactory.getLog(getClass());

	/**
	 * CsrfToken的存储策略
	 */
	private final CsrfTokenRepository csrfTokenRepository;

	/**
	 * Creates a new instance
	 * @param csrfTokenRepository the {@link CsrfTokenRepository} to use
	 */
	public CsrfAuthenticationStrategy(CsrfTokenRepository csrfTokenRepository) {
		Assert.notNull(csrfTokenRepository, "csrfTokenRepository cannot be null");
		this.csrfTokenRepository = csrfTokenRepository;
	}

	/**
	 * 认证成功后，更换新的csrfToken
	 * @param authentication 创建的正确的认证对象，而不是由用户输入的用户名和密码构建的
	 * @param request
	 * @param response
	 * @throws SessionAuthenticationException
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException {
		boolean containsToken = this.csrfTokenRepository.loadToken(request) != null;
		//如果原来没有csrfToken，那也就不需要换新的csrfToken
		if (containsToken) {
			//清空原csrfToken
			this.csrfTokenRepository.saveToken(null, request, response);
			CsrfToken newToken = this.csrfTokenRepository.generateToken(request);
			//保存新csrfToken
			this.csrfTokenRepository.saveToken(newToken, request, response);
			//将CsrfToken给调用方
			//request中的属性会被SpringMvc的Model操作
			request.setAttribute(CsrfToken.class.getName(), newToken);
			request.setAttribute(newToken.getParameterName(), newToken);
			this.logger.debug("Replaced CSRF Token");
		}
	}

}
