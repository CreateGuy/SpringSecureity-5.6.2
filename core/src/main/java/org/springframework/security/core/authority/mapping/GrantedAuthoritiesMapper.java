/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.core.authority.mapping;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * 权限映射接口
 * 比如A角色有B和C的角色，那么{@link org.springframework.security.access.hierarchicalroles.RoleHierarchyAuthoritiesMapper}
 * 就负责将A变成 A,B,C然后保存到用户认证对象中
 */
public interface GrantedAuthoritiesMapper {

	/**
	 * 权限转换
	 * @param authorities
	 * @return
	 */
	Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities);

}
