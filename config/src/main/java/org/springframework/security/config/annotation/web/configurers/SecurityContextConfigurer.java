/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * SecurityContextPersistenceFilter的配置类
 */
public final class SecurityContextConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<SecurityContextConfigurer<H>, H> {

	/**
	 * Creates a new instance
	 * @see HttpSecurity#securityContext()
	 */
	public SecurityContextConfigurer() {
	}

	/**
	 * 添加一个HttpSession级别的安全上下文存储策略
	 * @param securityContextRepository
	 * @return
	 */
	public SecurityContextConfigurer<H> securityContextRepository(SecurityContextRepository securityContextRepository) {
		//往HttpSecurity中添加一个HttpSession级别的安全上下文存储策略
		getBuilder().setSharedObject(SecurityContextRepository.class, securityContextRepository);
		return this;
	}

	@Override
	@SuppressWarnings("unchecked")
	public void configure(H http) {
		//获得HttpSession级别的安全上下文存储策略
		SecurityContextRepository securityContextRepository = http.getSharedObject(SecurityContextRepository.class);
		//如果没有就创建默认的
		if (securityContextRepository == null) {
			securityContextRepository = new HttpSessionSecurityContextRepository();
		}
		//创建过滤器
		SecurityContextPersistenceFilter securityContextFilter = new SecurityContextPersistenceFilter(
				securityContextRepository);
		//从HttpSecurity中获得会话管理配配置类
		SessionManagementConfigurer<?> sessionManagement = http.getConfigurer(SessionManagementConfigurer.class);
		SessionCreationPolicy sessionCreationPolicy = (sessionManagement != null)
				? sessionManagement.getSessionCreationPolicy() : null;
		//看会话管理配配置类是否允许一直创建Session
		//这样的话SecurityContextPersistenceFilter就直接使用request.getSession()创建session
		if (SessionCreationPolicy.ALWAYS == sessionCreationPolicy) {
			securityContextFilter.setForceEagerSessionCreation(true);
		}
		securityContextFilter = postProcess(securityContextFilter);
		http.addFilter(securityContextFilter);
	}

}
