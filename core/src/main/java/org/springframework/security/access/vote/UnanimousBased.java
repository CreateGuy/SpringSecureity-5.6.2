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

package org.springframework.security.access.vote;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * 所有投票器都必须投同意票的 访问决策管理器
 */
public class UnanimousBased extends AbstractAccessDecisionManager {

	public UnanimousBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}

	/**
	 * This concrete implementation polls all configured {@link AccessDecisionVoter}s for
	 * each {@link ConfigAttribute} and grants access if <b>only</b> grant (or abstain)
	 * votes were received.
	 * <p>
	 * Other voting implementations usually pass the entire list of
	 * <tt>ConfigAttribute</tt>s to the <code>AccessDecisionVoter</code>. This
	 * implementation differs in that each <code>AccessDecisionVoter</code> knows only
	 * about a single <code>ConfigAttribute</code> at a time.
	 * <p>
	 * If every <code>AccessDecisionVoter</code> abstained from voting, the decision will
	 * be based on the {@link #isAllowIfAllAbstainDecisions()} property (defaults to
	 * false).
	 * @param authentication the caller invoking the method
	 * @param object the secured object
	 * @param attributes the configuration attributes associated with the method being
	 * invoked
	 * @throws AccessDeniedException if access is denied
	 */
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> attributes)
			throws AccessDeniedException {
		int grant = 0;
		List<ConfigAttribute> singleAttributeList = new ArrayList<>(1);
		singleAttributeList.add(null);
		for (ConfigAttribute attribute : attributes) {
			singleAttributeList.set(0, attribute);
			for (AccessDecisionVoter voter : getDecisionVoters()) {
				int result = voter.vote(authentication, object, singleAttributeList);
				switch (result) {
				case AccessDecisionVoter.ACCESS_GRANTED:
					grant++;
					break;
				//一旦有拒绝票，就直接抛出异常
				case AccessDecisionVoter.ACCESS_DENIED:
					throw new AccessDeniedException(
							this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
				default:
					break;
				}
			}
		}
		//走到这，就代表没有拒绝票，而且有同意票
		if (grant > 0) {
			return;
		}
		//走到这一步，就代表所有访问决策投票器都弃权了
		checkAllowIfAllAbstainDecisions();
	}

}
