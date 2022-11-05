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

package org.springframework.security.crypto.password;

import java.util.HashMap;
import java.util.Map;

/**
 * 基于前缀标识符委托给另一个PasswordEncoder的密码编码器。
 * 好处1：兼容性
 * 好处1：便捷性
 * 好处1：稳定性
 *
 * <h2>Constructing an instance</h2>
 *
 * You can easily construct an instance using
 * {@link org.springframework.security.crypto.factory.PasswordEncoderFactories}.
 * Alternatively, you may create your own custom instance. For example:
 *
 * <pre>
 * String idForEncode = "bcrypt";
 * Map&lt;String,PasswordEncoder&gt; encoders = new HashMap&lt;&gt;();
 * encoders.put(idForEncode, new BCryptPasswordEncoder());
 * encoders.put("noop", NoOpPasswordEncoder.getInstance());
 * encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
 * encoders.put("scrypt", new SCryptPasswordEncoder());
 * encoders.put("sha256", new StandardPasswordEncoder());
 *
 * PasswordEncoder passwordEncoder = new DelegatingPasswordEncoder(idForEncode, encoders);
 * </pre>
 *
 *
 * <h2>Password Storage Format</h2>
 *
 * The general format for a password is:
 *
 * <pre>
 * {id}encodedPassword
 * </pre>
 *
 * Such that "id" is an identifier used to look up which {@link PasswordEncoder} should be
 * used and "encodedPassword" is the original encoded password for the selected
 * {@link PasswordEncoder}. The "id" must be at the beginning of the password, start with
 * "{" and end with "}". If the "id" cannot be found, the "id" will be null.
 *
 * For example, the following might be a list of passwords encoded using different "id".
 * All of the original passwords are "password".
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * {noop}password
 * {pbkdf2}5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc
 * {scrypt}$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc=
 * {sha256}97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0
 * </pre>
 *
 * For the DelegatingPasswordEncoder that we constructed above:
 *
 * <ol>
 * <li>The first password would have a {@code PasswordEncoder} id of "bcrypt" and
 * encodedPassword of "$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG". When
 * matching it would delegate to
 * {@link org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder}</li>
 * <li>The second password would have a {@code PasswordEncoder} id of "noop" and
 * encodedPassword of "password". When matching it would delegate to
 * {@link NoOpPasswordEncoder}</li>
 * <li>The third password would have a {@code PasswordEncoder} id of "pbkdf2" and
 * encodedPassword of
 * "5d923b44a6d129f3ddf3e3c8d29412723dcbde72445e8ef6bf3b508fbf17fa4ed4d6b99ca763d8dc".
 * When matching it would delegate to {@link Pbkdf2PasswordEncoder}</li>
 * <li>The fourth password would have a {@code PasswordEncoder} id of "scrypt" and
 * encodedPassword of
 * "$e0801$8bWJaSu2IKSn9Z9kM+TPXfOc/9bdYSrN1oD9qfVThWEwdRTnO7re7Ei+fUZRJ68k9lTyuTeUp4of4g24hHnazw==$OAOec05+bXxvuu/1qZ6NUR+xQYvYv7BeL1QxwRpY5Pc="
 * When matching it would delegate to
 * {@link org.springframework.security.crypto.scrypt.SCryptPasswordEncoder}</li>
 * <li>The final password would have a {@code PasswordEncoder} id of "sha256" and
 * encodedPassword of
 * "97cde38028ad898ebc02e690819fa220e88c62e0699403e94fff291cfffaf8410849f27605abcbc0".
 * When matching it would delegate to {@link StandardPasswordEncoder}</li>
 * </ol>
 *
 * <h2>Password Encoding</h2>
 *
 * The {@code idForEncode} passed into the constructor determines which
 * {@link PasswordEncoder} will be used for encoding passwords. In the
 * {@code DelegatingPasswordEncoder} we constructed above, that means that the result of
 * encoding "password" would be delegated to {@code BCryptPasswordEncoder} and be prefixed
 * with "{bcrypt}". The end result would look like:
 *
 * <pre>
 * {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
 * </pre>
 *
 * <h2>Password Matching</h2>
 *
 * Matching is done based upon the "id" and the mapping of the "id" to the
 * {@link PasswordEncoder} provided in the constructor. Our example in "Password Storage
 * Format" provides a working example of how this is done.
 *
 * By default the result of invoking {@link #matches(CharSequence, String)} with a
 * password with an "id" that is not mapped (including a null id) will result in an
 * {@link IllegalArgumentException}. This behavior can be customized using
 * {@link #setDefaultPasswordEncoderForMatches(PasswordEncoder)}.
 *
 * @author Rob Winch
 * @author Michael Simons
 * @since 5.0
 * @see org.springframework.security.crypto.factory.PasswordEncoderFactories
 */
public class DelegatingPasswordEncoder implements PasswordEncoder {

	private static final String PREFIX = "{";

	private static final String SUFFIX = "}";

	/**
	 * 当前系统指定的密码编码器名称
	 */
	private final String idForEncode;

	/**
	 * 当前系统指定的密码编码器
	 */
	private final PasswordEncoder passwordEncoderForEncode;

	/**
	 * 密码编码器集合
	 * 用于适配其他加密方式的密码(比如说加密方式进行了升级，但是老数据的密码还是要支持)
	 */
	private final Map<String, PasswordEncoder> idToPasswordEncoder;

	/**
	 * 无法通过密码格式获取密码编码器的时候而使用密码编码器
	 */
	private PasswordEncoder defaultPasswordEncoderForMatches = new UnmappedIdPasswordEncoder();

	/**
	 * 设置密码编码器集合，同时也会设置默认的密码编码器
	 * @param idForEncode 默认密码编码器名称
	 * @param idToPasswordEncoder
	 */
	public DelegatingPasswordEncoder(String idForEncode, Map<String, PasswordEncoder> idToPasswordEncoder) {
		if (idForEncode == null) {
			throw new IllegalArgumentException("idForEncode cannot be null");
		}
		if (!idToPasswordEncoder.containsKey(idForEncode)) {
			throw new IllegalArgumentException(
					"idForEncode " + idForEncode + "is not found in idToPasswordEncoder " + idToPasswordEncoder);
		}
		for (String id : idToPasswordEncoder.keySet()) {
			if (id == null) {
				continue;
			}
			//密码编码器名称不能以{开头
			if (id.contains(PREFIX)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + PREFIX);
			}
			//密码编码器名称不能以}开头
			if (id.contains(SUFFIX)) {
				throw new IllegalArgumentException("id " + id + " cannot contain " + SUFFIX);
			}
		}
		this.idForEncode = idForEncode;
		this.passwordEncoderForEncode = idToPasswordEncoder.get(idForEncode);
		this.idToPasswordEncoder = new HashMap<>(idToPasswordEncoder);
	}

	/**
	 * 设置保底的密码编码器
	 * @param defaultPasswordEncoderForMatches
	 */
	public void setDefaultPasswordEncoderForMatches(PasswordEncoder defaultPasswordEncoderForMatches) {
		if (defaultPasswordEncoderForMatches == null) {
			throw new IllegalArgumentException("defaultPasswordEncoderForMatches cannot be null");
		}
		this.defaultPasswordEncoderForMatches = defaultPasswordEncoderForMatches;
	}

	/**
	 * 对密码进行编码，可以看到密码的格式就是 {密码编码器名称} + 编码后的密码
	 * 这样为什么能通过密码解析出密码编码器的原因
	 * @param rawPassword
	 * @return
	 */
	@Override
	public String encode(CharSequence rawPassword) {
		return PREFIX + this.idForEncode + SUFFIX + this.passwordEncoderForEncode.encode(rawPassword);
	}

	/**
	 * 对密码进行匹配
	 * @param rawPassword 用户输入的密码
	 * @param prefixEncodedPassword 保存的密码 eg：{bcrypt}12q31s23
	 * @return
	 */
	@Override
	public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
		if (rawPassword == null && prefixEncodedPassword == null) {
			return true;
		}
		//获得密码编码器名称
		String id = extractId(prefixEncodedPassword);
		//获得密码编码器
		PasswordEncoder delegate = this.idToPasswordEncoder.get(id);
		if (delegate == null) {
			//到这就说明无法通过密码获取密码编码器，只能用默认的密码编码器
			return this.defaultPasswordEncoderForMatches.matches(rawPassword, prefixEncodedPassword);
		}
		//取出真实密码
		String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
		//真正开始匹配的地方
		return delegate.matches(rawPassword, encodedPassword);
	}

	/**
	 * 获得密码编码器名称
	 * @param prefixEncodedPassword
	 * @return
	 */
	private String extractId(String prefixEncodedPassword) {
		if (prefixEncodedPassword == null) {
			return null;
		}
		int start = prefixEncodedPassword.indexOf(PREFIX);
		if (start != 0) {
			return null;
		}
		int end = prefixEncodedPassword.indexOf(SUFFIX, start);
		if (end < 0) {
			return null;
		}
		return prefixEncodedPassword.substring(start + 1, end);
	}

	/**
	 * 是否能对密码进行更新
	 * @param prefixEncodedPassword 编码后的密码
	 * @return
	 */
	@Override
	public boolean upgradeEncoding(String prefixEncodedPassword) {
		String id = extractId(prefixEncodedPassword);
		//如果当密码不是由当前系统指定密码编码器创建出来的，那就直接返回false
		if (!this.idForEncode.equalsIgnoreCase(id)) {
			return true;
		}
		else {
			String encodedPassword = extractEncodedPassword(prefixEncodedPassword);
			return this.idToPasswordEncoder.get(id).upgradeEncoding(encodedPassword);
		}
	}

	/**
	 * 取出真实密码
	 * @param prefixEncodedPassword
	 * @return
	 */
	private String extractEncodedPassword(String prefixEncodedPassword) {
		int start = prefixEncodedPassword.indexOf(SUFFIX);
		return prefixEncodedPassword.substring(start + 1);
	}

	/**
	 * 默认的PasswordEncoder，它会直接抛出一个异常
	 */
	private class UnmappedIdPasswordEncoder implements PasswordEncoder {

		@Override
		public String encode(CharSequence rawPassword) {
			throw new UnsupportedOperationException("encode is not supported");
		}

		@Override
		public boolean matches(CharSequence rawPassword, String prefixEncodedPassword) {
			String id = extractId(prefixEncodedPassword);
			throw new IllegalArgumentException("There is no PasswordEncoder mapped for the id \"" + id + "\"");
		}

	}

}
