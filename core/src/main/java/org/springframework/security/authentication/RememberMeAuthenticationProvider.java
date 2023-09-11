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

package org.springframework.security.authentication;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 * 记住我登录的认证提供者
 */
public class RememberMeAuthenticationProvider implements AuthenticationProvider, InitializingBean, MessageSourceAware {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	/**
	 * 记住我秘钥
	 */
	private String key;

	public RememberMeAuthenticationProvider(String key) {
		Assert.hasLength(key, "key must have a length");
		this.key = key;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notNull(this.messages, "A message source must be set");
	}

	/**
	 * 记住我的认证规则很简单，只比较了秘钥
	 * <p>我理解是因为在通过记住我过滤器生成记住我认证对象的时候，已经比较过签名了</p>
	 * @param authentication the authentication request object.
	 * @return
	 * @throws AuthenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (!supports(authentication.getClass())) {
			return null;
		}
		//比较秘钥是否相同
		if (this.key.hashCode() != ((RememberMeAuthenticationToken) authentication).getKeyHash()) {
			throw new BadCredentialsException(this.messages.getMessage("RememberMeAuthenticationProvider.incorrectKey",
					"The presented RememberMeAuthenticationToken does not contain the expected key"));
		}
		return authentication;
	}

	public String getKey() {
		return this.key;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return (RememberMeAuthenticationToken.class.isAssignableFrom(authentication));
	}

}
