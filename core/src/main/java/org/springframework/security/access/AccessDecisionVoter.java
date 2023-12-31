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

import org.springframework.security.core.Authentication;

/**
 * 访问决策投票器
 */
public interface AccessDecisionVoter<S> {

	/**
	 * 同意票
	 */
	int ACCESS_GRANTED = 1;

	/**
	 * 弃权票
	 */
	int ACCESS_ABSTAIN = 0;

	/**
	 * 拒绝票
	 */
	int ACCESS_DENIED = -1;

	/**
	 * 指示这个访问决策投票器是否能够对传递的ConfigAttribute进行投票
	 * This allows the {@code AbstractSecurityInterceptor} to check every configuration
	 * attribute can be consumed by the configured {@code AccessDecisionManager} and/or
	 * {@code RunAsManager} and/or {@code AfterInvocationManager}.
	 * @param attribute a configuration attribute that has been configured against the
	 * {@code AbstractSecurityInterceptor}
	 * @return true if this {@code AccessDecisionVoter} can support the passed
	 * configuration attribute
	 */
	boolean supports(ConfigAttribute attribute);

	/**
	 * 指示这个访问决策投票器是否为指定的安全对象类型提供访问控制投票
	 * @param clazz the class that is being queried
	 * @return true if the implementation can process the indicated class
	 */
	boolean supports(Class<?> clazz);

	/**
	 * 投票
	 * <p>
	 * The decision must be affirmative ({@code ACCESS_GRANTED}), negative (
	 * {@code ACCESS_DENIED}) or the {@code AccessDecisionVoter} can abstain (
	 * {@code ACCESS_ABSTAIN}) from voting. Under no circumstances should implementing
	 * classes return any other value. If a weighting of results is desired, this should
	 * be handled in a custom
	 * {@link org.springframework.security.access.AccessDecisionManager} instead.
	 * <p>
	 * Unless an {@code AccessDecisionVoter} is specifically intended to vote on an access
	 * control decision due to a passed method invocation or configuration attribute
	 * parameter, it must return {@code ACCESS_ABSTAIN}. This prevents the coordinating
	 * {@code AccessDecisionManager} from counting votes from those
	 * {@code AccessDecisionVoter}s without a legitimate interest in the access control
	 * decision.
	 * <p>
	 * Whilst the secured object (such as a {@code MethodInvocation}) is passed as a
	 * parameter to maximise flexibility in making access control decisions, implementing
	 * classes should not modify it or cause the represented invocation to take place (for
	 * example, by calling {@code MethodInvocation.proceed()}).
	 * @param authentication the caller making the invocation
	 * @param object the secured object being invoked
	 * @param attributes the configuration attributes associated with the secured object
	 * @return either {@link #ACCESS_GRANTED}, {@link #ACCESS_ABSTAIN} or
	 * {@link #ACCESS_DENIED}
	 */
	int vote(Authentication authentication, S object, Collection<ConfigAttribute> attributes);

}
