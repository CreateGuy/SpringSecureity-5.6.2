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

/**
 * 是在身份认证成功发生时 执行有关HttpSession的策略
 * 默认会有一个防止固定会话攻击的 改变sessionId的策略
 */
public interface SessionAuthenticationStrategy {

	/**
	 * 比如说在UsernamePasswordAuthenticationFilter中认证通过了就会执行
	 * @param authentication 创建的正确的认证对象，而不是由用户输入的用户名和密码构建的
	 * @param request
	 * @param response
	 * @throws SessionAuthenticationException
	 */
	void onAuthentication(Authentication authentication, HttpServletRequest request, HttpServletResponse response)
			throws SessionAuthenticationException;

}
