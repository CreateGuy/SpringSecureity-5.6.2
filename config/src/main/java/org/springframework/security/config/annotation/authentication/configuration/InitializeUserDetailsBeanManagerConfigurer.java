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
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 主要为了给全局认证管理器添加一个的认证提供者
 * 与{@link InitializeAuthenticationProviderBeanManagerConfigurer}
 * 的区别：这个类是通过获取认证提供者所有需要的UserDetailsService，PasswordEncoder等等来组合成一个认证提供者
 */
@Order(InitializeUserDetailsBeanManagerConfigurer.DEFAULT_ORDER)
class InitializeUserDetailsBeanManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

	static final int DEFAULT_ORDER = Ordered.LOWEST_PRECEDENCE - 5000;

	private final ApplicationContext context;

	/**
	 * @param context
	 */
	InitializeUserDetailsBeanManagerConfigurer(ApplicationContext context) {
		this.context = context;
	}

	/**
	 * 为了给全局认证管理器构建器添加一个InitializeUserDetailsManagerConfigurer？？，那为什么不一开始就添加？？，搞不懂
	 * @param auth 一般情况都是全局认证管理器构建器
	 * @throws Exception
	 */
	@Override
	public void init(AuthenticationManagerBuilder auth) throws Exception {
		auth.apply(new InitializeUserDetailsManagerConfigurer());
	}

	class InitializeUserDetailsManagerConfigurer extends GlobalAuthenticationConfigurerAdapter {

		/**
		 * 尝试获得有关认证的相关对象
		 * @param auth 一般情况都是全局认证管理器
		 * @throws Exception
		 */
		@Override
		public void configure(AuthenticationManagerBuilder auth) throws Exception {
			if (auth.isConfigured()) {
				return;
			}
			//尝试获取UserDetailsService
			UserDetailsService userDetailsService = getBeanOrNull(UserDetailsService.class);
			//如果UserDetailsService都没有，都不能加载用户，也就用不着PasswordEncoder，那就直接返回
			if (userDetailsService == null) {
				return;
			}
			//尝试获取PasswordEncoder
			PasswordEncoder passwordEncoder = getBeanOrNull(PasswordEncoder.class);
			//尝试获取UserDetailsPasswordService
			UserDetailsPasswordService passwordManager = getBeanOrNull(UserDetailsPasswordService.class);
			//创建一个默认的认证提供者，并设置相关属性
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userDetailsService);
			if (passwordEncoder != null) {
				provider.setPasswordEncoder(passwordEncoder);
			}
			if (passwordManager != null) {
				provider.setUserDetailsPasswordService(passwordManager);
			}
			provider.afterPropertiesSet();
			//给全局认证管理器添加一个默认的认证提供者
			auth.authenticationProvider(provider);
		}

		/**
		 * 如果只找到一个bean，则返回被请求类的bean，否则返回null
		 * @param type
		 */
		private <T> T getBeanOrNull(Class<T> type) {
			String[] beanNames = InitializeUserDetailsBeanManagerConfigurer.this.context.getBeanNamesForType(type);
			if (beanNames.length != 1) {
				return null;
			}
			return InitializeUserDetailsBeanManagerConfigurer.this.context.getBean(beanNames[0], type);
		}

	}

}
