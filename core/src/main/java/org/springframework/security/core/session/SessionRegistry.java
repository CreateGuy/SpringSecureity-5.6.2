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

import java.util.List;

/**
 * SessionInformation注册中心
 * @see SessionRegistryImpl
 */
public interface SessionRegistry {

	/**
	 * Obtains all the known principals in the <code>SessionRegistry</code>.
	 * @return each of the unique principals, which can then be presented to
	 * {@link #getAllSessions(Object, boolean)}.
	 */
	List<Object> getAllPrincipals();

	/**
	 * 获得当前用户所有的 {@link SessionInformation}
	 * @param principal to locate sessions for (should never be <code>null</code>)
	 * @param includeExpiredSessions if <code>true</code>, the returned sessions will also
	 * include those that have expired for the principal
	 * @return the matching sessions for this principal (should not return null).
	 */
	List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions);

	/**
	 * 获取指定sessionId的 {@link SessionInformation}。甚至会返回过期的会话(尽管永远不会返回已销毁的会话)
	 * @param sessionId to lookup (should never be <code>null</code>)
	 * @return the session information, or <code>null</code> if not found
	 */
	SessionInformation getSessionInformation(String sessionId);

	/**
	 * 刷新当前sessionId对应的 {@link SessionInformation} 的最后一次操作时间
	 * @param sessionId for which to update the date and time of the last request (should
	 * never be <code>null</code>)
	 */
	void refreshLastRequest(String sessionId);

	/**
	 * 注册新的映射关系, 新注册的会话不会被标记为过期
	 * @param sessionId to associate with the principal (should never be <code>null</code>
	 * )
	 * @param principal to associate with the session (should never be <code>null</code>)
	 */
	void registerNewSession(String sessionId, Object principal);

	/**
	 * 清除有关此sessionId的映射关系
	 * @param sessionId to delete information for (should never be <code>null</code>)
	 */
	void removeSessionInformation(String sessionId);

}
