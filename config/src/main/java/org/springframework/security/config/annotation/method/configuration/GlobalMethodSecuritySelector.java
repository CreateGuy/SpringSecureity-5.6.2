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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

/**
 * 由 {@link EnableGlobalMethodSecurity @EnableGlobalMethodSecurity} 确定哪些权限注解能开启
 *
 * @author Rob Winch
 * @since 3.2
 */
final class GlobalMethodSecuritySelector implements ImportSelector {

	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		Class<EnableGlobalMethodSecurity> annoType = EnableGlobalMethodSecurity.class;
		// 获得导入类上有关EnableGlobalMethodSecurity的属性
		Map<String, Object> annotationAttributes = importingClassMetadata.getAnnotationAttributes(annoType.getName(),
				false);
		AnnotationAttributes attributes = AnnotationAttributes.fromMap(annotationAttributes);
		Assert.notNull(attributes, () -> String.format("@%s is not present on importing class '%s' as expected",
				annoType.getSimpleName(), importingClassMetadata.getClassName()));

		// TODO would be nice if could use BeanClassLoaderAware (does not work)
		Class<?> importingClass = ClassUtils.resolveClassName(importingClassMetadata.getClassName(),
				ClassUtils.getDefaultClassLoader());
		boolean skipMethodSecurityConfiguration = GlobalMethodSecurityConfiguration.class
				.isAssignableFrom(importingClass);

		// 设置有关代理属性
		// 默认就是AdviceMode.PROXY
		AdviceMode mode = attributes.getEnum("mode");
		boolean isProxy = AdviceMode.PROXY == mode;
		String autoProxyClassName = isProxy ? AutoProxyRegistrar.class.getName()
				: GlobalMethodSecurityAspectJAutoProxyRegistrar.class.getName();


		boolean jsr250Enabled = attributes.getBoolean("jsr250Enabled");
		List<String> classNames = new ArrayList<>(4);

		// 默认就是True
		if (isProxy) {
			// 重点：注册一个Advisor
			classNames.add(MethodSecurityMetadataSourceAdvisorRegistrar.class.getName());
		}

		classNames.add(autoProxyClassName);

		// 注册权限注解的基本配置类
		if (!skipMethodSecurityConfiguration) {
			classNames.add(GlobalMethodSecurityConfiguration.class.getName());
		}

		// 注册
		if (jsr250Enabled) {
			classNames.add(Jsr250MetadataSourceConfiguration.class.getName());
		}
		return classNames.toArray(new String[0]);
	}

}
