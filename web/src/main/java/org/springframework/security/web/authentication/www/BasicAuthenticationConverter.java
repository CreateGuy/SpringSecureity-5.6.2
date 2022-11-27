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

package org.springframework.security.web.authentication.www;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * 从HttpServletRequest获取某些参数然后转换为认证对象，
 * 如果没有请求头中的Authorization没有以Basic开头的，则可能存在空身份认证
 */
public class BasicAuthenticationConverter implements AuthenticationConverter {

	/**
	 * 基本认证传输的用户名和密码采用Basic64加密，然后前面有一个Basic
	 * <li>
	 *     eg：Authorization: Basic bHp4OjEyMw==
	 * </li>
	 */
	public static final String AUTHENTICATION_SCHEME_BASIC = "Basic";

	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

	/**
	 * 解密Base64字符串的编码格式
	 */
	private Charset credentialsCharset = StandardCharsets.UTF_8;

	public BasicAuthenticationConverter() {
		this(new WebAuthenticationDetailsSource());
	}

	public BasicAuthenticationConverter(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	public Charset getCredentialsCharset() {
		return this.credentialsCharset;
	}

	public void setCredentialsCharset(Charset credentialsCharset) {
		this.credentialsCharset = credentialsCharset;
	}

	public AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
		return this.authenticationDetailsSource;
	}

	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource, "AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}

	/**
	 * 通过解析request中的某些参数转为认证对象
	 * @param request
	 * @return
	 */
	@Override
	public UsernamePasswordAuthenticationToken convert(HttpServletRequest request) {
		//用户名+密码是放在Authorization中的
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		if (header == null) {
			return null;
		}
		header = header.trim();
		//没有Basic开头，就返回空
		if (!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BASIC)) {
			return null;
		}
		//Basic64不能为空
		if (header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BASIC)) {
			throw new BadCredentialsException("Empty basic authentication token");
		}
		//去除前面的Basic+空格
		byte[] base64Token = header.substring(6).getBytes(StandardCharsets.UTF_8);
		byte[] decoded = decode(base64Token);
		//解密
		String token = new String(decoded, getCredentialsCharset(request));

		//确定用户名和密码的分隔符在哪
		int delim = token.indexOf(":");
		if (delim == -1) {
			throw new BadCredentialsException("Invalid basic authentication token");
		}

		//封装为认证对象
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(token.substring(0, delim),
				token.substring(delim + 1));
		result.setDetails(this.authenticationDetailsSource.buildDetails(request));
		return result;
	}

	private byte[] decode(byte[] base64Token) {
		try {
			return Base64.getDecoder().decode(base64Token);
		}
		catch (IllegalArgumentException ex) {
			throw new BadCredentialsException("Failed to decode basic authentication token");
		}
	}

	protected Charset getCredentialsCharset(HttpServletRequest request) {
		return getCredentialsCharset();
	}

}
