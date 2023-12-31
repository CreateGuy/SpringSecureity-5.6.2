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

package org.springframework.security.access.intercept;

import java.util.Collection;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.context.SecurityContext;

/**
 * A return object received by {@link AbstractSecurityInterceptor} subclasses.
 * <p>
 * This class reflects the status of the security interception, so that the final call to
 * {@link org.springframework.security.access.intercept.AbstractSecurityInterceptor#afterInvocation(InterceptorStatusToken, Object)}
 * can tidy up correctly.
 *
 * @author Ben Alex
 */
public class InterceptorStatusToken {

	/**
	 * 最新的安全上下文，也有可能是以前的
	 * <p>以前的情况是因为 {@link RunAsManager}</p>
	 */
	private SecurityContext securityContext;

	/**
	 * 通过安全元数据获得接口所需权限
	 */
	private Collection<ConfigAttribute> attr;

	private Object secureObject;

	/**
	 * 是否需要恢复认证对象
	 */
	private boolean contextHolderRefreshRequired;

	public InterceptorStatusToken(SecurityContext securityContext, boolean contextHolderRefreshRequired,
			Collection<ConfigAttribute> attributes, Object secureObject) {
		this.securityContext = securityContext;
		this.contextHolderRefreshRequired = contextHolderRefreshRequired;
		this.attr = attributes;
		this.secureObject = secureObject;
	}

	public Collection<ConfigAttribute> getAttributes() {
		return this.attr;
	}

	public SecurityContext getSecurityContext() {
		return this.securityContext;
	}

	public Object getSecureObject() {
		return this.secureObject;
	}

	public boolean isContextHolderRefreshRequired() {
		return this.contextHolderRefreshRequired;
	}

}
