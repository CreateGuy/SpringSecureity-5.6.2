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

package org.springframework.security.access.prepost;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * 根据 {@link PreFilter @PreFilter} 和 {@link PreAuthorize @PreAuthorize} 进行投票
 * <p>
 * In practice, if these annotations are being used, they will normally contain all the
 * necessary access control logic, so a voter-based system is not really necessary and a
 * single <tt>AccessDecisionManager</tt> which contained the same logic would suffice.
 * However, this class fits in readily with the traditional voter-based
 * <tt>AccessDecisionManager</tt> implementations used by Spring Security.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PreInvocationAuthorizationAdviceVoter implements AccessDecisionVoter<MethodInvocation> {

	protected final Log logger = LogFactory.getLog(getClass());

	private final PreInvocationAuthorizationAdvice preAdvice;

	public PreInvocationAuthorizationAdviceVoter(PreInvocationAuthorizationAdvice pre) {
		this.preAdvice = pre;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof PreInvocationAttribute;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return MethodInvocation.class.isAssignableFrom(clazz);
	}

	@Override
	public int vote(Authentication authentication, MethodInvocation method, Collection<ConfigAttribute> attributes) {
		// 找到pre的权限表达式
		PreInvocationAttribute preAttr = findPreInvocationAttribute(attributes);
		if (preAttr == null) {
			// 没有权限表达式，投弃权票
			return ACCESS_ABSTAIN;
		}
		// 在方法执行前进行投票
		return this.preAdvice.before(authentication, method, preAttr) ? ACCESS_GRANTED : ACCESS_DENIED;
	}

	/**
	 * 找到pre的权限表达式
	 * <li>通常来源是 {@link PreFilter @PreFilter} 和 {@link PreAuthorize @PreAuthorize}</li>
	 * @param config
	 * @return
	 */
	private PreInvocationAttribute findPreInvocationAttribute(Collection<ConfigAttribute> config) {
		for (ConfigAttribute attribute : config) {
			if (attribute instanceof PreInvocationAttribute) {
				return (PreInvocationAttribute) attribute;
			}
		}
		return null;
	}

}
