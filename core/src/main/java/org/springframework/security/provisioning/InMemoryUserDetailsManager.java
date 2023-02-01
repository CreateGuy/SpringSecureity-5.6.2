/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.provisioning;

import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.memory.UserAttribute;
import org.springframework.security.core.userdetails.memory.UserAttributeEditor;
import org.springframework.util.Assert;

/**
 * {@link UserDetailsManager} 的非持久实现，它由内存映射支持。
 * 主要用于测试和演示目的，其中不需要完整的持久系统
 */
public class InMemoryUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {

	protected final Log logger = LogFactory.getLog(getClass());

	/**
	 * 存储在内存中的用户
	 */
	private final Map<String, MutableUserDetails> users = new HashMap<>();

	/**
	 * 认证管理器
	 */
	private AuthenticationManager authenticationManager;

	public InMemoryUserDetailsManager() {
	}

	public InMemoryUserDetailsManager(Collection<UserDetails> users) {
		for (UserDetails user : users) {
			createUser(user);
		}
	}

	public InMemoryUserDetailsManager(UserDetails... users) {
		for (UserDetails user : users) {
			createUser(user);
		}
	}

	public InMemoryUserDetailsManager(Properties users) {
		Enumeration<?> names = users.propertyNames();
		UserAttributeEditor editor = new UserAttributeEditor();
		while (names.hasMoreElements()) {
			String name = (String) names.nextElement();
			editor.setAsText(users.getProperty(name));
			UserAttribute attr = (UserAttribute) editor.getValue();
			Assert.notNull(attr,
					() -> "The entry with username '" + name + "' could not be converted to an UserDetails");
			createUser(createUserDetails(name, attr));
		}
	}

	private User createUserDetails(String name, UserAttribute attr) {
		return new User(name, attr.getPassword(), attr.isEnabled(), true, true, true, attr.getAuthorities());
	}

	@Override
	public void createUser(UserDetails user) {
		Assert.isTrue(!userExists(user.getUsername()), "user should not exist");
		this.users.put(user.getUsername().toLowerCase(), new MutableUser(user));
	}

	@Override
	public void deleteUser(String username) {
		this.users.remove(username.toLowerCase());
	}

	@Override
	public void updateUser(UserDetails user) {
		Assert.isTrue(userExists(user.getUsername()), "user should exist");
		this.users.put(user.getUsername().toLowerCase(), new MutableUser(user));
	}

	@Override
	public boolean userExists(String username) {
		return this.users.containsKey(username.toLowerCase());
	}

	/**
	 * 基于内存的更新密码
	 * @param oldPassword current password (for re-authentication if required)
	 * @param newPassword the password to change to
	 */
	@Override
	public void changePassword(String oldPassword, String newPassword) {
		Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();
		if (currentUser == null) {
			// This would indicate bad coding somewhere
			throw new AccessDeniedException(
					"Can't change password as no Authentication object found in context " + "for current user.");
		}
		String username = currentUser.getName();
		this.logger.debug(LogMessage.format("Changing password for user '%s'", username));
		// 如果设置了认证管理器，使用旧密码再验证一次
		if (this.authenticationManager != null) {
			this.logger.debug(LogMessage.format("Reauthenticating user '%s' for password change request.", username));
			this.authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, oldPassword));
		}
		else {
			this.logger.debug("No authentication manager set. Password won't be re-checked.");
		}

		// 更新密码
		MutableUserDetails user = this.users.get(username);
		Assert.state(user != null, "Current user doesn't exist in database.");
		user.setPassword(newPassword);
	}

	/**
	 * 基于内存的更新密码
	 * @param user 源UserDetails
	 * @param newPassword 新密码
	 * @return
	 */
	@Override
	public UserDetails updatePassword(UserDetails user, String newPassword) {
		String username = user.getUsername();
		MutableUserDetails mutableUser = this.users.get(username.toLowerCase());
		mutableUser.setPassword(newPassword);
		return mutableUser;
	}

	/**
	 * 根据用户名加载用户对象
	 * @param username the username identifying the user whose data is required.
	 * @return
	 * @throws UsernameNotFoundException
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserDetails user = this.users.get(username.toLowerCase());
		if (user == null) {
			throw new UsernameNotFoundException(username);
		}
		return new User(user.getUsername(), user.getPassword(), user.isEnabled(), user.isAccountNonExpired(),
				user.isCredentialsNonExpired(), user.isAccountNonLocked(), user.getAuthorities());
	}

	public void setAuthenticationManager(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
