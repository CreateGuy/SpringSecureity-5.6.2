/*
 * Copyright 2002-2020 the original author or authors.
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

import java.util.Comparator;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.session.ConcurrentSessionFilter;
import org.springframework.security.web.session.SessionManagementFilter;
import org.springframework.util.Assert;

/**
 * 处理并发会话控制的策略
 */
public class ConcurrentSessionControlAuthenticationStrategy
		implements MessageSourceAware, SessionAuthenticationStrategy {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * SessionInformation注册中心
	 */
	private final SessionRegistry sessionRegistry;

	/**
	 * 某个用户的会话数达到maximumSessions的时候，是否阻止登录
	 * <ul>
	 *     <li>
	 * 			true: 后面登录的用户直接抛出异常
	 *     </li>
	 *     <li>
	 *			false：将最先登录的那个会话对应的SessionInformation直接设置为已过期，那么遇到ConcurrentSessionFilter就会有对应的退出操作了
	 *     </li>
	 * </ul>
	 */
	private boolean exceptionIfMaximumExceeded = false;

	/**
	 * 最大会话并发数
	 */
	private int maximumSessions = 1;

	/**
	 * @param sessionRegistry the session registry which should be updated when the
	 * authenticated session is changed.
	 */
	public ConcurrentSessionControlAuthenticationStrategy(SessionRegistry sessionRegistry) {
		Assert.notNull(sessionRegistry, "The sessionRegistry cannot be null");
		this.sessionRegistry = sessionRegistry;
	}

	/**
	 *
	 * @param authentication 创建的正确的认证对象，而不是由用户输入的用户名和密码构建的
	 * @param request
	 * @param response
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		//先获取最大并发数
		int allowedSessions = getMaximumSessionsForThisUser(authentication);
		//如果是-1表示不限制，那么就直接返回
		if (allowedSessions == -1) {
			// We permit unlimited logins
			return;
		}

		//通过SessionInformation注册中心获得当前用户的所有SessionInformation
		List<SessionInformation> sessions = this.sessionRegistry.getAllSessions(authentication.getPrincipal(), false);
		int sessionCount = sessions.size();
		//如果小于最大并发数据，就可以返回了
		if (sessionCount < allowedSessions) {
			// They haven't got too many login sessions running at present
			return;
		}
		//如果数量相等的情况
		if (sessionCount == allowedSessions) {
			HttpSession session = request.getSession(false);
			if (session != null) {
				//只要当前会话在当前用户的SessionInformation集合里面
				//比如有最大限制2，有A和B，B进到自然能够匹配sessionId，也就可以继续后面的操作了
				for (SessionInformation si : sessions) {
					if (si.getSessionId().equals(session.getId())) {
						return;
					}
				}
			}
			//走到这里表示已经达到最大限制了，而且并不是其中的一个
		}
		//已经超过了最大会话数了，要么踢出某个会话，要么抛出异常
		allowableSessionsExceeded(sessions, allowedSessions, this.sessionRegistry);
	}

	/**
	 * Method intended for use by subclasses to override the maximum number of sessions
	 * that are permitted for a particular authentication. The default implementation
	 * simply returns the <code>maximumSessions</code> value for the bean.
	 * @param authentication to determine the maximum sessions for
	 * @return either -1 meaning unlimited, or a positive integer to limit (never zero)
	 */
	protected int getMaximumSessionsForThisUser(Authentication authentication) {
		return this.maximumSessions;
	}

	/**
	 * 已经超过了最大会话数了，要么踢出某个会话，要么抛出异常
	 * @param sessions 当前用户的所有SessionInformation
	 * @param allowableSessions 最大并发数
	 * @param registry
	 * @throws SessionAuthenticationException
	 */
	protected void allowableSessionsExceeded(List<SessionInformation> sessions, int allowableSessions,
			SessionRegistry registry) throws SessionAuthenticationException {
		//阻止当前会话登录此用户，直接抛出异常
		if (this.exceptionIfMaximumExceeded || (sessions == null)) {
			throw new SessionAuthenticationException(
					this.messages.getMessage("ConcurrentSessionControlAuthenticationStrategy.exceededAllowed",
							new Object[] { allowableSessions }, "Maximum sessions of {0} for this principal exceeded"));
		}
		//踢出最早没有操作的会话
		//对SessionInformation的最后一次操作时间进行排序
		sessions.sort(Comparator.comparing(SessionInformation::getLastRequest));
		//需要踢出的数量
		int maximumSessionsExceededBy = sessions.size() - allowableSessions + 1;
		//拿到需要踢出的SessionInformation
		List<SessionInformation> sessionsToBeExpired = sessions.subList(0, maximumSessionsExceededBy);
		//标记这些SessionInformation为已过期
		//这样ConcurrentSessionFilter就会对于这些已过期的SessionInformation对应的会话执行登出操作
		for (SessionInformation session : sessionsToBeExpired) {
			session.expireNow();
		}
	}

	/**
	 * Sets the <tt>exceptionIfMaximumExceeded</tt> property, which determines whether the
	 * user should be prevented from opening more sessions than allowed. If set to
	 * <tt>true</tt>, a <tt>SessionAuthenticationException</tt> will be raised which means
	 * the user authenticating will be prevented from authenticating. if set to
	 * <tt>false</tt>, the user that has already authenticated will be forcibly logged
	 * out.
	 * @param exceptionIfMaximumExceeded defaults to <tt>false</tt>.
	 */
	public void setExceptionIfMaximumExceeded(boolean exceptionIfMaximumExceeded) {
		this.exceptionIfMaximumExceeded = exceptionIfMaximumExceeded;
	}

	/**
	 * Sets the <tt>maxSessions</tt> property. The default value is 1. Use -1 for
	 * unlimited sessions.
	 * @param maximumSessions the maximimum number of permitted sessions a user can have
	 * open simultaneously.
	 */
	public void setMaximumSessions(int maximumSessions) {
		Assert.isTrue(maximumSessions != 0,
				"MaximumLogins must be either -1 to allow unlimited logins, or a positive integer to specify a maximum");
		this.maximumSessions = maximumSessions;
	}

	/**
	 * Sets the {@link MessageSource} used for reporting errors back to the user when the
	 * user has exceeded the maximum number of authentications.
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
