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

package org.springframework.security.web.authentication.logout;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * 清空线程级别上下文的登出处理器
 */
public class SecurityContextLogoutHandler implements LogoutHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());

	/**
	 * 是否应该在登出时 使Session无效
	 */
	private boolean invalidateHttpSession = true;

	/**
	 * 是否应该在登出时 清除认证对象
	 */
	private boolean clearAuthentication = true;

	/**
	 * 清空当前用户的安全上下文
	 * @param request the HTTP request
	 * @param response the HTTP response
	 * @param authentication the current principal details
	 */
	@Override
	public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
		Assert.notNull(request, "HttpServletRequest required");
		//是否使Session无效
		if (this.invalidateHttpSession) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				session.invalidate();
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(LogMessage.format("Invalidated session %s", session.getId()));
				}
			}
		}

		//清空当前用户的 线程级别的安全上下文
		//HttpSession级别的在SecurityContextPersistenceFilter中会被清除
		SecurityContext context = SecurityContextHolder.getContext();
		SecurityContextHolder.clearContext();
		//清空认证对象
		if (this.clearAuthentication) {
			context.setAuthentication(null);
		}
	}

	public boolean isInvalidateHttpSession() {
		return this.invalidateHttpSession;
	}

	/**
	 *
	 */
	public void setInvalidateHttpSession(boolean invalidateHttpSession) {
		this.invalidateHttpSession = invalidateHttpSession;
	}

	/**
	 * If true, removes the {@link Authentication} from the {@link SecurityContext} to
	 * prevent issues with concurrent requests.
	 * @param clearAuthentication true if you wish to clear the {@link Authentication}
	 * from the {@link SecurityContext} (default) or false if the {@link Authentication}
	 * should not be removed.
	 */
	public void setClearAuthentication(boolean clearAuthentication) {
		this.clearAuthentication = clearAuthentication;
	}

}
