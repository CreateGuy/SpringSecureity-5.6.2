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

import java.util.Collection;
import java.util.List;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * 只要有任何一个投票器投了同意一票，就可以的 访问决策管理器
 */
public class AffirmativeBased extends AbstractAccessDecisionManager {

	public AffirmativeBased(List<AccessDecisionVoter<?>> decisionVoters) {
		super(decisionVoters);
	}

	/**
	 * 只要有任何一个投票器投了同意一票，就可以
	 */
	@Override
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void decide(Authentication authentication, Object object, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException {
		int deny = 0;
		for (AccessDecisionVoter voter : getDecisionVoters()) {
			//调用投票器进行投票
			int result = voter.vote(authentication, object, configAttributes);
			switch (result) {
				//有任何一个同意就可以
				case AccessDecisionVoter.ACCESS_GRANTED:
					return;
				case AccessDecisionVoter.ACCESS_DENIED:
					deny++;
					break;
				default:
					break;
			}
		}
		//有任何一个拒绝就抛出异常
		if (deny > 0) {
			throw new AccessDeniedException(
					this.messages.getMessage("AbstractAccessDecisionManager.accessDenied", "Access is denied"));
		}
		//走到这一步，就代表所有访问决策投票器都弃权了
		checkAllowIfAllAbstainDecisions();
	}

}
