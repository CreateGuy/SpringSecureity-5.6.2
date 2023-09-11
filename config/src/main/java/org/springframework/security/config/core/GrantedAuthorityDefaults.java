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

package org.springframework.security.config.core;

import org.springframework.security.core.GrantedAuthority;

/**
 * 角色前缀
 */
public final class GrantedAuthorityDefaults {

	private final String rolePrefix;

	public GrantedAuthorityDefaults(String rolePrefix) {
		this.rolePrefix = rolePrefix;
	}

	/**
	 * 基于角色的授权使用的默认前缀。默认为 ROLE_
	 * @return the default role prefix
	 */
	public String getRolePrefix() {
		return this.rolePrefix;
	}

}
