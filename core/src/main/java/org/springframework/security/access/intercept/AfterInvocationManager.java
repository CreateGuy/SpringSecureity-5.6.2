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

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * 执行后管理器
 * <ul>
 *     <li>是为了在执行目标方法后，继续操作</li>
 * </ul>
 */
public interface AfterInvocationManager {

	/**
	 * 根据处理方法执行后权限表达式和返回值进行操作
	 * @param authentication the caller that invoked the method
	 * @param object the secured object that was called
	 * @param attributes the configuration attributes associated with the secured object
	 * that was invoked
	 * @param returnedObject the <code>Object</code> that was returned from the secure
	 * object invocation
	 * @return the <code>Object</code> that will ultimately be returned to the caller (if
	 * an implementation does not wish to modify the object to be returned to the caller,
	 * the implementation should simply return the same object it was passed by the
	 * <code>returnedObject</code> method argument)
	 * @throws AccessDeniedException if access is denied
	 */
	Object decide(Authentication authentication, Object object, Collection<ConfigAttribute> attributes,
			Object returnedObject) throws AccessDeniedException;

	/**
	 * 此 {@link AfterInvocationManager} 是否支持解析 {@link ConfigAttribute}
	 * <p>
	 * This allows the <code>AbstractSecurityInterceptor</code> to check every
	 * configuration attribute can be consumed by the configured
	 * <code>AccessDecisionManager</code> and/or <code>RunAsManager</code> and/or
	 * <code>AfterInvocationManager</code>.
	 * </p>
	 * @param attribute a configuration attribute that has been configured against the
	 * <code>AbstractSecurityInterceptor</code>
	 * @return true if this <code>AfterInvocationManager</code> can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * Indicates whether the <code>AfterInvocationManager</code> implementation is able to
	 * provide access control decisions for the indicated secured object type.
	 * @param clazz the class that is being queried
	 * @return <code>true</code> if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

}
