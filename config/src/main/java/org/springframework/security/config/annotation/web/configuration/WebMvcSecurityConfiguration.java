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

package org.springframework.security.config.annotation.web.configuration;

import java.util.List;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.expression.BeanFactoryResolver;
import org.springframework.expression.BeanResolver;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.method.annotation.CsrfTokenArgumentResolver;
import org.springframework.security.web.method.annotation.CurrentSecurityContextArgumentResolver;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * <ol>
 *     <li>
 *         为了SpringMvc添加一个 {@link CsrfRequestDataValueProcessor}
 *     </li>
 *     <li>
 *         添加有关SpringSecurity相关的参数解析器
 *     </li>
 * </ol>
 *
 */
class WebMvcSecurityConfiguration implements WebMvcConfigurer, ApplicationContextAware {

	private BeanResolver beanResolver;

	@Override
	@SuppressWarnings("deprecation")
	public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
		AuthenticationPrincipalArgumentResolver authenticationPrincipalResolver = new AuthenticationPrincipalArgumentResolver();
		authenticationPrincipalResolver.setBeanResolver(this.beanResolver);
		argumentResolvers.add(authenticationPrincipalResolver);
		argumentResolvers
				.add(new org.springframework.security.web.bind.support.AuthenticationPrincipalArgumentResolver());

		CurrentSecurityContextArgumentResolver currentSecurityContextArgumentResolver = new CurrentSecurityContextArgumentResolver();
		currentSecurityContextArgumentResolver.setBeanResolver(this.beanResolver);
		argumentResolvers.add(currentSecurityContextArgumentResolver);
		// 注册 CsrfToken 的参数解析器
		argumentResolvers.add(new CsrfTokenArgumentResolver());
	}

	@Bean
	RequestDataValueProcessor requestDataValueProcessor() {
		return new CsrfRequestDataValueProcessor();
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.beanResolver = new BeanFactoryResolver(applicationContext.getAutowireCapableBeanFactory());
	}

}
