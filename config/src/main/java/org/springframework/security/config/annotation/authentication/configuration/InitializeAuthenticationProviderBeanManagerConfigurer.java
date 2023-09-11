/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configuration;

import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

/**
 * 为了给全局认证管理器设置认证提供者
 */
@Order(InitializeAuthenticationProviderBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeAuthenticationProviderBeanManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER - 100;

	private final ApplicationContext context;

	/**
	 * @param context the ApplicationContext to look up beans.
	 */
	InitializeAuthenticationProviderBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * 为了给全局认证管理器构建器添加一个InitializeAuthenticationProviderManagerConfigurer？？，那为什么不一开始就添加？？，搞不懂
	 * @param auth 一般情况都是全局认证管理器构建器
	 * @throws Exception
	 */
	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.apply(new InitializeAuthenticationProviderManagerConfigurer());
	}

	class InitializeAuthenticationProviderManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

		/**
		 * 尝试从容器中获取认证提供者
		 * @param auth
		 */
		@Override
		public void configure(AuthenticationManagerBuilder auth) {
			if (auth.isConfigured()) {
				return;
			}
			AuthenticationProvider authenticationProvider = getBeanOrNull(AuthenticationProvider.class);
			if (authenticationProvider == null) {
				return;
			}
			//将认证提供者添加到对应集合中
			auth.authenticationProvider(authenticationProvider);
		}

		/**
		 * @return a bean of the requested class if there's just a single registered
		 * component, null otherwise.
		 */
		private <T> T getBeanOrNull(Class<T> type) {
			String[] beanNames = InitializeAuthenticationProviderBeanManagerConfigurer.this.context
					.getBeanNamesForType(type);
			if (beanNames.length != 1) {
				return null;
			}
			return InitializeAuthenticationProviderBeanManagerConfigurer.this.context.getBean(beanNames[0], type);
		}

	}

}
