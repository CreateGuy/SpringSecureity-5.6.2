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

package org.springframework.security.access;

import java.util.Collection;

import org.springframework.security.access.intercept.AfterInvocationProviderManager;
import org.springframework.security.core.Authentication;

/**
 * 请求处理方法执行后在 {@link AfterInvocationProviderManager} 中负责调用，确定最后的返回值
 * <li>比如说过滤返回值，判断权限</li>
 */
public interface AfterInvocationProvider {

	/**
	 * 对于返回值和权限进行判断
	 * <<li>其实就是 {@link org.springframework.security.access.prepost.PostFilter @PostFilter} 和 {@link org.springframework.security.access.prepost.PostAuthorize @PostAuthorize}</li>
	 * @param authentication
	 * @param object
	 * @param attributes
	 * @param returnedObject
	 * @return
	 * @throws AccessDeniedException
	 */
	Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> attributes,
			Object returnedObject) throws AccessDeniedException;

	/**
	 * Indicates whether this <code>AfterInvocationProvider</code> is able to participate
	 * in a decision involving the passed <code>ConfigAttribute</code>.
	 * <p>
	 * This allows the <code>AbstractSecurityInterceptor</code> to check every
	 * configuration attribute can be consumed by the configured
	 * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code> and/or
	 * <code>AccessDecisionManager</code>.
	 * </p>
	 * @param attribute a configuration attribute that has been configured against the
	 * <code>AbstractSecurityInterceptor</code>
	 * @return true if this <code>AfterInvocationProvider</code> can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * Indicates whether the <code>AfterInvocationProvider</code> is able to provide
	 * "after invocation" processing for the indicated secured object type.
	 * @param clazz the class of secure object that is being queried
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

}
