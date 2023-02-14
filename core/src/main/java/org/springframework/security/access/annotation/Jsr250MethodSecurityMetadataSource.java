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

package org.springframework.security.access.annotation;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.method.AbstractFallbackMethodSecurityMetadataSource;

/**
 * 从 JSR 250 的注解中中获取方法安全元数据源
 * <li>{@link javax.annotation.security.RolesAllowed @RolesAllowed}.
 * {@link javax.annotation.security.PermitAll @RolesAllowed},
 * {@link javax.annotation.security.DenyAll @RolesAllowed}</li>
 */
public class Jsr250MethodSecurityMetadataSource extends AbstractFallbackMethodSecurityMetadataSource {

	/**
	 * 角色前缀
	 */
	private String defaultRolePrefix = "ROLE_";

	/**
	 * <p>
	 * Sets the default prefix to be added to {@link RolesAllowed}. For example, if
	 * {@code @RolesAllowed("ADMIN")} or {@code @RolesAllowed("ADMIN")} is used, then the
	 * role ROLE_ADMIN will be used when the defaultRolePrefix is "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 */
	public void setDefaultRolePrefix(String defaultRolePrefix) {
		this.defaultRolePrefix = defaultRolePrefix;
	}

	@Override
	protected Collection<ConfigAttribute> findAttributes(Class<?> clazz) {
		return processAnnotations(clazz.getAnnotations());
	}

	@Override
	protected Collection<ConfigAttribute> findAttributes(Method method, Class<?> targetClass) {
		return processAnnotations(AnnotationUtils.getAnnotations(method));
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		return null;
	}

	/**
	 * 获得指定指定注解的方法的权限表达式
	 * @param annotations
	 * @return
	 */
	private List<ConfigAttribute> processAnnotations(Annotation[] annotations) {
		if (annotations == null || annotations.length == 0) {
			return null;
		}
		List<ConfigAttribute> attributes = new ArrayList<>();
		for (Annotation annotation : annotations) {
			if (annotation instanceof DenyAll) {
				attributes.add(Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE);
				return attributes;
			}
			if (annotation instanceof PermitAll) {
				attributes.add(Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE);
				return attributes;
			}
			if (annotation instanceof RolesAllowed) {
				RolesAllowed ra = (RolesAllowed) annotation;

				// 给角色加上默认前缀
				for (String allowed : ra.value()) {
					String defaultedAllowed = getRoleWithDefaultPrefix(allowed);
					attributes.add(new Jsr250SecurityConfig(defaultedAllowed));
				}
				return attributes;
			}
		}
		return null;
	}

	/**
	 * 如果角色没有带默认前缀，那就加上
	 * @param role
	 * @return
	 */
	private String getRoleWithDefaultPrefix(String role) {
		if (role == null) {
			return role;
		}
		if (this.defaultRolePrefix == null || this.defaultRolePrefix.length() == 0) {
			return role;
		}
		if (role.startsWith(this.defaultRolePrefix)) {
			return role;
		}
		return this.defaultRolePrefix + role;
	}

}
