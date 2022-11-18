/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;

/**
 * 记住我服务
 *
 * <p>
 * Spring Security filters (namely
 * {@link org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter
 * AbstractAuthenticationProcessingFilter} and
 * {@link org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter
 * RememberMeAuthenticationFilter} will call the methods provided by an implementation of
 * this interface.
 * <p>
 * Implementations may implement any type of remember-me capability they wish. Rolling
 * cookies (as per <a href=
 * "https://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice">
 * https://fishbowl.pastiche.org/2004/01/19/persistent_login_cookie_best_practice</a>) can
 * be used, as can simple implementations that don't require a persistent store.
 * Implementations also determine the validity period of a remember-me cookie. This
 * interface has been designed to accommodate any of these remember-me models.
 * <p>
 * This interface does not define how remember-me services should offer a "cancel all
 * remember-me tokens" type capability, as this will be implementation specific and
 * requires no hooks into Spring Security.
 *
 * @author Ben Alex
 */
public interface RememberMeServices {

	/**
	 * 将记住我令牌转为认证对象
	 * @param request
	 * @param response
	 * @return
	 */
	Authentication autoLogin(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 认证失败调用的方法
	 * <ul>
	 *     <li>
	 *         比如说执行autoLogin方法创建的认证对象，认证失败后，清除记住我令牌
	 *     </li>
	 * </ul>
	 * @param request
	 * @param response
	 */
	void loginFail(HttpServletRequest request, HttpServletResponse response);

	/**
	 * 认证成功调用的方法
	 * <ul>
	 *     <li>
	 *         比如说使用表单或者基本认证，认证成功后，可能需要创建一个记住我令牌
	 *     </li>
	 * </ul>
	 */
	void loginSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication successfulAuthentication);

}
