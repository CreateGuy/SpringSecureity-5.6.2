/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.util.ClassUtils;

/**
 * 当使用了 {@link EnableWebSecurity} 注解会导入此导入选择器
 * {@link WebMvcSecurityConfiguration}
 */
class SpringWebMvcImportSelector implements ImportSelector {

	/**
	 * 当前类加载器能够加载 {@code DispatcherServlet} 的时候，向容器注册 {@code WebMvcSecurityConfiguration}
	 * @param importingClassMetadata
	 * @return
	 */
	@Override
	public String[] selectImports(AnnotationMetadata importingClassMetadata) {
		if (!ClassUtils.isPresent("org.springframework.web.servlet.DispatcherServlet", getClass().getClassLoader())) {
			return new String[0];
		}
		return new String[] {
				"org.springframework.security.config.annotation.web.configuration.WebMvcSecurityConfiguration" };
	}

}
