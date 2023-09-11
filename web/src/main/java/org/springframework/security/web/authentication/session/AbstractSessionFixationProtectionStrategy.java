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

package org.springframework.security.web.authentication.session;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

/**
 * 防止会话固定保护的基类
 */
public abstract class AbstractSessionFixationProtectionStrategy
		implements SessionAuthenticationStrategy, ApplicationEventPublisherAware {

	protected final Log logger = LogFactory.getLog(this.getClass());

	/**
	 * Used for publishing events related to session fixation protection, such as
	 * {@link SessionFixationProtectionEvent}.
	 */
	private ApplicationEventPublisher applicationEventPublisher = new NullEventPublisher();

	/**
	 * 如果设置为true，则将始终创建会话，即使在请求开始时不存在会话
	 */
	private boolean alwaysCreateSession;

	AbstractSessionFixationProtectionStrategy() {
	}

	/**
	 * Called when a user is newly authenticated.
	 * <p>
	 * If a session already exists, and matches the session Id from the client, a new
	 * session will be created, and the session attributes copied to it (if
	 * {@code migrateSessionAttributes} is set). If the client's requested session Id is
	 * invalid, nothing will be done, since there is no need to change the session Id if
	 * it doesn't match the current session.
	 * <p>
	 * If there is no session, no action is taken unless the {@code alwaysCreateSession}
	 * property is set, in which case a session will be created if one doesn't already
	 * exist.
	 */
	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) {
		boolean hadSessionAlready = request.getSession(false) != null;
		if (!hadSessionAlready && !this.alwaysCreateSession) {
			// 如果没有会话，就没有会话固定攻击
			return;
		}
		// 如果需要，创建新的会话
		HttpSession session = request.getSession();
		if (hadSessionAlready && request.isRequestedSessionIdValid()) {
			String originalSessionId;
			String newSessionId;
			// 获得此HttpSession的互斥锁
			Object mutex = WebUtils.getSessionMutex(session);
			synchronized (mutex) {
				// We need to migrate to a new session
				originalSessionId = session.getId();
				session = applySessionFixation(request);
				newSessionId = session.getId();
			}
			if (originalSessionId.equals(newSessionId)) {
				this.logger.warn("Your servlet container did not change the session ID when a new session "
						+ "was created. You will not be adequately protected against session-fixation attacks");
			}
			else {
				if (this.logger.isDebugEnabled()) {
					this.logger.debug(LogMessage.format("Changed session id from %s", originalSessionId));
				}
			}
			// 发布会话ID变更事件
			onSessionChange(originalSessionId, session, authentication);
		}
	}

	/**
	 * Applies session fixation
	 * @param request the {@link HttpServletRequest} to apply session fixation protection
	 * for
	 * @return the new {@link HttpSession} to use. Cannot be null.
	 */
	abstract HttpSession applySessionFixation(HttpServletRequest request);

	/**
	 * Called when the session has been changed and the old attributes have been migrated
	 * to the new session. Only called if a session existed to start with. Allows
	 * subclasses to plug in additional behaviour. *
	 * <p>
	 * The default implementation of this method publishes a
	 * {@link SessionFixationProtectionEvent} to notify the application that the session
	 * ID has changed. If you override this method and still wish these events to be
	 * published, you should call {@code super.onSessionChange()} within your overriding
	 * method.
	 * @param originalSessionId the original session identifier
	 * @param newSession the newly created session
	 * @param auth the token for the newly authenticated principal
	 */
	protected void onSessionChange(String originalSessionId, HttpSession newSession, Authentication auth) {
		this.applicationEventPublisher
				.publishEvent(new SessionFixationProtectionEvent(auth, originalSessionId, newSession.getId()));
	}

	/**
	 * Sets the {@link ApplicationEventPublisher} to use for submitting
	 * {@link SessionFixationProtectionEvent}. The default is to not submit the
	 * {@link SessionFixationProtectionEvent}.
	 * @param applicationEventPublisher the {@link ApplicationEventPublisher}. Cannot be
	 * null.
	 */
	@Override
	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		Assert.notNull(applicationEventPublisher, "applicationEventPublisher cannot be null");
		this.applicationEventPublisher = applicationEventPublisher;
	}

	public void setAlwaysCreateSession(boolean alwaysCreateSession) {
		this.alwaysCreateSession = alwaysCreateSession;
	}

	protected static final class NullEventPublisher implements ApplicationEventPublisher {

		@Override
		public void publishEvent(ApplicationEvent event) {
		}

		@Override
		public void publishEvent(Object event) {
		}

	}

}
