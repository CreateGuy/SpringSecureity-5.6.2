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

package org.springframework.security.config.annotation.method.configuration;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.intercept.aopalliance.MethodSecurityMetadataSourceAdvisor;
import org.springframework.util.MultiValueMap;

/**
 * 往容器中注册 {@link MethodSecurityMetadataSourceAdvisor} 对应的 {@link BeanDefinition}
 * @see GlobalMethodSecuritySelector
 */
class MethodSecurityMetadataSourceAdvisorRegistrar implements ImportBeanDefinitionRegistrar {

	/**
	 * Register, escalate, and configure the AspectJ auto proxy creator based on the value
	 * of the @{@link EnableGlobalMethodSecurity#proxyTargetClass()} attribute on the
	 * importing {@code @Configuration} class.
	 */
	@Override
	public void registerBeanDefinitions(AnnotationMetadata importingClassMetadata, BeanDefinitionRegistry registry) {
		// 拿到Advice
		BeanDefinitionBuilder advisor = BeanDefinitionBuilder
				.rootBeanDefinition(MethodSecurityMetadataSourceAdvisor.class);
		// 设置此Bean的角色
		advisor.setRole(BeanDefinition.ROLE_INFRASTRUCTURE);

		// 设置构造方法参数列表
		// 详情见MethodSecurityMetadataSourceAdvisor的构造方法
		advisor.addConstructorArgValue("methodSecurityInterceptor");
		// 这个指的是第二个参数必须是这个类型的
		advisor.addConstructorArgReference("methodSecurityMetadataSource");
		advisor.addConstructorArgValue("methodSecurityMetadataSource");

		// 设置Bean实例化的顺序
		MultiValueMap<String, Object> attributes = importingClassMetadata
				.getAllAnnotationAttributes(EnableGlobalMethodSecurity.class.getName());
		Integer order = (Integer) attributes.getFirst("order");
		if (order != null) {
			advisor.addPropertyValue("order", order);
		}

		// 往Bean工厂中注册此BeanDefinition
		registry.registerBeanDefinition("metaDataSourceAdvisor", advisor.getBeanDefinition());
	}

}
