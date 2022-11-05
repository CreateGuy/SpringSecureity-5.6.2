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

package org.springframework.security.core.userdetails;

/**
 * 密码更新器
 * 用于更改UserDetails密码
 * 实现类只有关于内存用户的修改，如果说要更改数据库的密码，要自己写实现类
 */
public interface UserDetailsPasswordService {

	/**
	 * 修改指定用户的密码。这会更改持久用户存储库(数据库、LDAP等)中的用户密码。
	 * @param user 源UserDetails
	 * @param newPassword 新密码
	 * @return 修改后UserDetails
	 */
	UserDetails updatePassword(UserDetails user, String newPassword);

}
