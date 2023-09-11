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

package org.springframework.security.core.session;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationListener;
import org.springframework.core.log.LogMessage;
import org.springframework.util.Assert;

/**
 * 针对SpringSecurity内部维护的SessionInformation的操作
 * 比如说用户登录后，才会创建会话session，那么通常会有一个SpringSecurity的SessionInformation的创建
 */
public class SessionRegistryImpl implements SessionRegistry, ApplicationListener<AbstractSessionEvent> {

	protected final Log logger = LogFactory.getLog(SessionRegistryImpl.class);

	/**
	 * user和HttpSessionId的映射关系
	 * 注意：user类是重写了equals方法的，这样就能存储某个用户对应的所有sessionId了
	 */
	private final ConcurrentMap<Object, Set<String>> principals;

	/**
	 * 是sessionId到SessionInformation的映射关系
	 */
	private final Map<String, SessionInformation> sessionIds;

	public SessionRegistryImpl() {
		this.principals = new ConcurrentHashMap<>();
		this.sessionIds = new ConcurrentHashMap<>();
	}

	public SessionRegistryImpl(ConcurrentMap<Object, Set<String>> principals,
			Map<String, SessionInformation> sessionIds) {
		this.principals = principals;
		this.sessionIds = sessionIds;
	}

	@Override
	public List<Object> getAllPrincipals() {
		return new ArrayList<>(this.principals.keySet());
	}

	/**
	 * 获得当前用户所有的SessionInformation
	 * @param principal 一般是User类或者及其子类
	 * @param includeExpiredSessions 是否需要过期的SessionInformation
	 * @return
	 */
	@Override
	public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
		//先获取当前用户名下的所有SessionId
		Set<String> sessionsUsedByPrincipal = this.principals.get(principal);
		if (sessionsUsedByPrincipal == null) {
			return Collections.emptyList();
		}
		//获得当前用户名下的所有SessionInformation
		List<SessionInformation> list = new ArrayList<>(sessionsUsedByPrincipal.size());
		for (String sessionId : sessionsUsedByPrincipal) {
			SessionInformation sessionInformation = getSessionInformation(sessionId);
			if (sessionInformation == null) {
				continue;
			}
			//过期了是否需要添加进去
			if (includeExpiredSessions || !sessionInformation.isExpired()) {
				list.add(sessionInformation);
			}
		}
		return list;
	}

	@Override
	public SessionInformation getSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		return this.sessionIds.get(sessionId);
	}

	/**
	 * 处理session无效而导致的销毁事件和sessionId发生改变的事件
	 * @param event
	 */
	@Override
	public void onApplicationEvent(AbstractSessionEvent event) {
		//处理销毁事件
		if (event instanceof SessionDestroyedEvent) {
			SessionDestroyedEvent sessionDestroyedEvent = (SessionDestroyedEvent) event;
			String sessionId = sessionDestroyedEvent.getId();
			//清除有关sessionId的映射关系
			removeSessionInformation(sessionId);
		}
		//处理sessionId发生改变事件
		//比如说为了防止会话固定攻击的ChangeSessionIdAuthenticationStrategy，就会在认证成功后改变SessionId
		else if (event instanceof SessionIdChangedEvent) {
			SessionIdChangedEvent sessionIdChangedEvent = (SessionIdChangedEvent) event;
			String oldSessionId = sessionIdChangedEvent.getOldSessionId();
			//要确保旧sessionId在session注册中心中
			if (this.sessionIds.containsKey(oldSessionId)) {
				Object principal = this.sessionIds.get(oldSessionId).getPrincipal();
				//清除有关旧sessionId的映射关系
				removeSessionInformation(oldSessionId);
				//注册新的映射关系
				registerNewSession(sessionIdChangedEvent.getNewSessionId(), principal);
			}
		}
	}

	/**
	 * 刷新当前sessionId对应的SessionInformation的最后一次操作时间
	 * @param sessionId for which to update the date and time of the last request (should
	 */
	@Override
	public void refreshLastRequest(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		//获得对应的SessionInformation
		SessionInformation info = getSessionInformation(sessionId);
		if (info != null) {
			info.refreshLastRequest();
		}
	}

	/**
	 * 注册新的映射关系
	 * @param sessionId to associate with the principal (should never be <code>null</code>
	 * )
	 * @param principal to associate with the session (should never be <code>null</code>)
	 */
	@Override
	public void registerNewSession(String sessionId, Object principal) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		Assert.notNull(principal, "Principal required as per interface contract");
		//如果原来还有就先删除映射关系
		if (getSessionInformation(sessionId) != null) {
			removeSessionInformation(sessionId);
		}
		if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Registering session %s, for principal %s", sessionId, principal));
		}
		//保存新的映射关系
		this.sessionIds.put(sessionId, new SessionInformation(principal, sessionId, new Date()));
		//这个方法的意思是当principal不在principals中，
		this.principals.compute(principal, (key, sessionsUsedByPrincipal) -> {
			if (sessionsUsedByPrincipal == null) {
				sessionsUsedByPrincipal = new CopyOnWriteArraySet<>();
			}
			sessionsUsedByPrincipal.add(sessionId);
			this.logger.trace(LogMessage.format("Sessions used by '%s' : %s", principal, sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

	/**
	 * 清除有关sessionId的映射关系
	 * @param sessionId 旧sessionId
	 */
	@Override
	public void removeSessionInformation(String sessionId) {
		Assert.hasText(sessionId, "SessionId required as per interface contract");
		//拿到SessionInformation
		SessionInformation info = getSessionInformation(sessionId);
		//为空就不需要清除了
		if (info == null) {
			return;
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.debug("Removing session " + sessionId + " from set of registered sessions");
		}
		//清除映射关系
		this.sessionIds.remove(sessionId);
		//由于principals相当于用户名到SessionId集合的映射
		//所以只需要删除旧的一个就可以了
		this.principals.computeIfPresent(info.getPrincipal(), (key, sessionsUsedByPrincipal) -> {
			this.logger.debug(
					LogMessage.format("Removing session %s from principal's set of registered sessions", sessionId));
			//删除这个SessionId集合中的某一个SessionId
			sessionsUsedByPrincipal.remove(sessionId);
			if (sessionsUsedByPrincipal.isEmpty()) {
				// No need to keep object in principals Map anymore
				this.logger.debug(LogMessage.format("Removing principal %s from registry", info.getPrincipal()));
				sessionsUsedByPrincipal = null;
			}
			this.logger.trace(
					LogMessage.format("Sessions used by '%s' : %s", info.getPrincipal(), sessionsUsedByPrincipal));
			return sessionsUsedByPrincipal;
		});
	}

}
