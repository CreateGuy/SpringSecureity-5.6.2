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

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.springframework.core.log.LogMessage;

/**
 * 使用HttpServletRequest.invalidate()来防止会话固定攻击
 * <p>
 * Creates a new session for the newly authenticated user if they already have a session
 * (as a defence against session-fixation protection attacks), and copies their session
 * attributes across to the new session. The copying of the attributes can be disabled by
 * setting {@code migrateSessionAttributes} to {@code false} (note that even in this case,
 * internal Spring Security attributes will still be migrated to the new session).
 * <p>
 * This approach will only be effective if your servlet container always assigns a new
 * session Id when a session is invalidated and a new session created by calling
 * {@link HttpServletRequest#getSession()}.
 * <p>
 * <h3>Issues with {@code HttpSessionBindingListener}</h3>
 * <p>
 * The migration of existing attributes to the newly-created session may cause problems if
 * any of the objects implement the {@code HttpSessionBindingListener} interface in a way
 * which makes assumptions about the life-cycle of the object. An example is the use of
 * Spring session-scoped beans, where the initial removal of the bean from the session
 * will cause the {@code DisposableBean} interface to be invoked, in the assumption that
 * the bean is no longer required.
 * <p>
 * We'd recommend that you take account of this when designing your application and do not
 * store attributes which may not function correctly when they are removed and then placed
 * back in the session. Alternatively, you should customize the
 * {@code SessionAuthenticationStrategy} to deal with the issue in an application-specific
 * way.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SessionFixationProtectionStrategy extends AbstractSessionFixationProtectionStrategy {

	/**
	 * 是否将现有Session的属性迁移至新Session
	 */
	boolean migrateSessionAttributes = true;

	/**
	 * 提取此 {@link HttpSession} 中的所有数据
	 * <p>
	 * You can override this method to control exactly what is transferred to the new
	 * session.
	 * @param session the session from which the attributes should be extracted
	 * @return the map of session attributes which should be transferred to the new
	 * session
	 */
	protected Map<String, Object> extractAttributes(HttpSession session) {
		return createMigratedAttributeMap(session);
	}

	@Override
	final HttpSession applySessionFixation(HttpServletRequest request) {
		HttpSession session = request.getSession();
		String originalSessionId = session.getId();
		this.logger.debug(LogMessage.of(() -> "Invalidating session with Id '" + originalSessionId + "' "
				+ (this.migrateSessionAttributes ? "and" : "without") + " migrating attributes."));
		// 提取此 HttpSession 中的所有数据
		Map<String, Object> attributesToMigrate = extractAttributes(session);
		int maxInactiveIntervalToMigrate = session.getMaxInactiveInterval();
		session.invalidate();
		session = request.getSession(true); // we now have a new session
		this.logger.debug(LogMessage.format("Started new session: %s", session.getId()));
		// 复制数据到新的HttpSession中
		transferAttributes(attributesToMigrate, session);
		if (this.migrateSessionAttributes) {
			session.setMaxInactiveInterval(maxInactiveIntervalToMigrate);
		}
		return session;
	}

	/**
	 * 复制数据到新的HttpSession中
	 * @param attributes the attributes which were extracted from the original session by
	 * {@code extractAttributes}
	 * @param newSession the newly created session
	 */
	void transferAttributes(Map<String, Object> attributes, HttpSession newSession) {
		if (attributes != null) {
			attributes.forEach(newSession::setAttribute);
		}
	}

	/**
	 * 提取此 {@link HttpSession} 中的所有数据
	 * @param session
	 * @return
	 */
	@SuppressWarnings("unchecked")
	private HashMap<String, Object> createMigratedAttributeMap(HttpSession session) {
		HashMap<String, Object> attributesToMigrate = new HashMap<>();
		Enumeration<String> enumeration = session.getAttributeNames();
		while (enumeration.hasMoreElements()) {
			String key = enumeration.nextElement();
			if (!this.migrateSessionAttributes && !key.startsWith("SPRING_SECURITY_")) {
				// Only retain Spring Security attributes
				continue;
			}
			attributesToMigrate.put(key, session.getAttribute(key));
		}
		return attributesToMigrate;
	}

	public void setMigrateSessionAttributes(boolean migrateSessionAttributes) {
		this.migrateSessionAttributes = migrateSessionAttributes;
	}

}
