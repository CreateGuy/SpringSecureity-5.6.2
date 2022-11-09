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

import java.io.Serializable;
import java.util.Date;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.util.Assert;

/**
 * 表示Spring Security框架内部的会话，这主要用于并发会话支持
 */
public class SessionInformation implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	/**
	 * 最后一次操作时间
	 */
	private Date lastRequest;

	/**
	 * 用户的主题，一般是User对象
	 */
	private final Object principal;

	private final String sessionId;

	/**
	 * 标记当前SessionInformation是否已经过期
	 * 一般是由于并发处理session的{@link ConcurrentSessionControlAuthenticationStrategy}设置的
	 */
	private boolean expired = false;

	public SessionInformation(Object principal, String sessionId, Date lastRequest) {
		Assert.notNull(principal, "Principal required");
		Assert.hasText(sessionId, "SessionId required");
		Assert.notNull(lastRequest, "LastRequest required");
		this.principal = principal;
		this.sessionId = sessionId;
		this.lastRequest = lastRequest;
	}

	public void expireNow() {
		this.expired = true;
	}

	public Date getLastRequest() {
		return this.lastRequest;
	}

	public Object getPrincipal() {
		return this.principal;
	}

	public String getSessionId() {
		return this.sessionId;
	}

	public boolean isExpired() {
		return this.expired;
	}

	/**
	 * 更新最后一次操作时间
	 */
	public void refreshLastRequest() {
		this.lastRequest = new Date();
	}

}
