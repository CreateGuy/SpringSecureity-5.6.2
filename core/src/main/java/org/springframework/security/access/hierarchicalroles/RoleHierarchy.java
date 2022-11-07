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

package org.springframework.security.access.hierarchicalroles;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;

/**
 * 角色继承器
 */
public interface RoleHierarchy {

	/**
	 * 将角色继承的角色也获取然后返回
	 * 比如：ROLE_A > ROLE_B > ROLE_C
	 * 那么当前用户就有A,B,C三种角色，而不是从持久化地方读取到的A角色
	 */
	Collection<? extends GrantedAuthority> getReachableGrantedAuthorities(
			Collection<? extends GrantedAuthority> authorities);

}
