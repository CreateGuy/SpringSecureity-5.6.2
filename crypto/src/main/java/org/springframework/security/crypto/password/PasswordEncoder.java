/*
 * Copyright 2011-2016 the original author or authors.
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

package org.springframework.security.crypto.password;

/**
 * 密码编码器
 */
public interface PasswordEncoder {

	/**
	 * 对原始密码进行编码
	 */
	String encode(CharSequence rawPassword);

	/**
	 * 验证密码是否匹配，该密码也进行了编码
	 * @param rawPassword
	 * @param encodedPassword
	 * @return
	 */
	boolean matches(CharSequence rawPassword, String encodedPassword);

	/**
	 * 如果编码后的密码应该重新编码以提高安全性，则返回true，否则返回false。
	 * 默认实现总是返回false
	 * @param encodedPassword
	 */
	default boolean upgradeEncoding(String encodedPassword) {
		return false;
	}

}
