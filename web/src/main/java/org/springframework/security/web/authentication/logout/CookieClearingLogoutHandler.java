/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 专用清除指定Cookie的登出处理器
 * 方式1：将指定Cookie的值设置为空
 * 方式2：将指定Cookie的生存时间设置为0
 */
public final class CookieClearingLogoutHandler implements LogoutHandler {

	private final List<Function<HttpServletRequest, Cookie>> cookiesToClear;

	/**
	 * 将指定Cookie的值设置为空
	 * @param cookiesToClear 需要清除Cookie的名称
	 */
	public CookieClearingLogoutHandler(String... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		List<Function<HttpServletRequest, Cookie>> cookieList = new ArrayList<>();
		for (String cookieName : cookiesToClear) {
			//添加清除函数
			cookieList.add((request) -> {
				//这里将指定名称的Cookie的Value设置为空
				Cookie cookie = new Cookie(cookieName, null);
				String contextPath = request.getContextPath();
				String cookiePath = StringUtils.hasText(contextPath) ? contextPath : "/";
				cookie.setPath(cookiePath);
				cookie.setMaxAge(0);
				//表明只能使用Https或者SSL
				cookie.setSecure(request.isSecure());
				return cookie;
			});
		}
		this.cookiesToClear = cookieList;
	}

	/**
	 * 将指定Cookie的生存时间设置为0
	 * @param cookiesToClear
	 */
	public CookieClearingLogoutHandler(Cookie... cookiesToClear) {
		Assert.notNull(cookiesToClear, "List of cookies cannot be null");
		List<Function<HttpServletRequest, Cookie>> cookieList = new ArrayList<>();
		for (Cookie cookie : cookiesToClear) {
			Assert.isTrue(cookie.getMaxAge() == 0, "Cookie maxAge must be 0");
			cookieList.add((request) -> cookie);
		}
		this.cookiesToClear = cookieList;
	}

	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		this.cookiesToClear.forEach((f) -> response.addCookie(f.apply(request)));
	}

}
