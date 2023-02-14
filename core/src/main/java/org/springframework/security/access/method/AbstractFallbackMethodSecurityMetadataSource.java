/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.access.method;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.Collections;

import org.springframework.aop.support.AopUtils;
import org.springframework.security.access.ConfigAttribute;

/**
 * Abstract implementation of {@link MethodSecurityMetadataSource} that supports both
 * Spring AOP and AspectJ and performs attribute resolution from: 1. specific target
 * method; 2. target class; 3. declaring method; 4. declaring class/interface. Use with
 * {@link DelegatingMethodSecurityMetadataSource} for caching support.
 * <p>
 * This class mimics the behaviour of Spring's
 * <tt>AbstractFallbackTransactionAttributeSource</tt> class.
 * <p>
 * Note that this class cannot extract security metadata where that metadata is expressed
 * by way of a target method/class (i.e. #1 and #2 above) AND the target method/class is
 * encapsulated in another proxy object. Spring Security does not walk a proxy chain to
 * locate the concrete/final target object. Consider making Spring Security your final
 * advisor (so it advises the final target, as opposed to another proxy), move the
 * metadata to declared methods or interfaces the proxy implements, or provide your own
 * replacement <tt>MethodSecurityMetadataSource</tt>.
 *
 * @author Ben Alex
 * @author Luke taylor
 * @since 2.0
 */
public abstract class AbstractFallbackMethodSecurityMetadataSource extends AbstractMethodSecurityMetadataSource {

	/**
	 * 返回执行传入的方法需要什么权限
	 * @param method
	 * @param targetClass
	 * @return
	 */
	@Override
	public Collection<ConfigAttribute> getAttributes(Method method, Class<?> targetClass) {
		// 如果传入的方法可能是来自接口，那么就找到具体的实现方法
		Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
		// 先找到方法上的权限表达式
		Collection<ConfigAttribute> attr = findAttributes(specificMethod, targetClass);
		if (attr != null) {
			return attr;
		}
		// 方法上没有找到，那就从方法的声明类上去查找
		attr = findAttributes(specificMethod.getDeclaringClass());
		if (attr != null) {
			return attr;
		}
		if (specificMethod != method || targetClass == null) {
			// 退一步看最初的方法
			attr = findAttributes(method, method.getDeclaringClass());
			if (attr != null) {
				return attr;
			}
			// 退一步看最初的方法的声明类
			return findAttributes(method.getDeclaringClass());
		}
		return Collections.emptyList();
	}

	/**
	 * 在方法上查找指定的权限注解，然后返回的权限表达式
	 * <p>
	 * Note that the {@link Method#getDeclaringClass()} may not equal the
	 * <code>targetClass</code>. Both parameters are provided to assist subclasses which
	 * may wish to provide advanced capabilities related to method metadata being
	 * "registered" against a method even if the target class does not declare the method
	 * (i.e. the subclass may only inherit the method).
	 * @param method the method for the current invocation (never <code>null</code>)
	 * @param targetClass the target class for the invocation (may be <code>null</code>)
	 * @return the security metadata (or null if no metadata applies)
	 */
	protected abstract Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass);

	/**
	 * 在类上查找指定的权限注解，然后返回的权限表达式
	 *
	 * <p>
	 * Subclasses should only return metadata expressed at a class level. Subclasses
	 * should NOT aggregate metadata for each method registered against a class, as the
	 * abstract superclass will separate invoke {@link #findAttributes(Method, Class)} for
	 * individual methods as appropriate.
	 * @param clazz the target class for the invocation (never <code>null</code>)
	 * @return the security metadata (or null if no metadata applies)
	 */
	protected abstract Collection<ConfigAttribute> findAttributes(Class<?> clazz);

}
