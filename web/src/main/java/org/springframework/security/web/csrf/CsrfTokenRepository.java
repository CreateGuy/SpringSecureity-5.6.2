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
import javax.servlet.http.HttpSession;

/**
 * CsrfToken的存储策略，有HttpSession和Cookie两种，但默认用的lazy+Session
 */
public interface CsrfTokenRepository {

	/**
	 * 生成 {@link CsrfToken}
	 * @param request the {@link HttpServletRequest} to use
	 * @return the {@link CsrfToken} that was generated. Cannot be null.
	 */
	CsrfToken generateToken(HttpServletRequest request);

	/**
	 * 使用 {@code HttpServletRequest} 和 {@code HttpServletResponse } 保存 {@code CsrfToken} 。如果{@code CsrfToken为空}，则与删除它
	 * @param token the {@link CsrfToken} to save or null to delete
	 * @param request the {@link HttpServletRequest} to use
	 * @param response the {@link HttpServletResponse} to use
	 */
	void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response);

	/**
	 * 从 {@code HttpServletRequest} 加载期望的 {@code CsrfToken}
	 * @param request the {@link HttpServletRequest} to use
	 * @return the {@link CsrfToken} or null if none exists
	 */
	CsrfToken loadToken(HttpServletRequest request);

}
