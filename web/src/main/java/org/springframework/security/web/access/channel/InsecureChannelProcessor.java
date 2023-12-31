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

package org.springframework.security.web.access.channel;

import java.io.IOException;
import java.util.Collection;

import javax.servlet.ServletException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

/**
 * 要求非安全通道的通道处理器
 * The class responds to one case-sensitive keyword, {@link #getInsecureKeyword}. If this
 * keyword is detected, <code>HttpServletRequest.isSecure()</code> is used to determine
 * the channel security offered. If channel security is present, the configured
 * <code>ChannelEntryPoint</code> is called. By default the entry point is
 * {@link RetryWithHttpEntryPoint}.
 * <p>
 * The default <code>insecureKeyword</code> is <code>REQUIRES_INSECURE_CHANNEL</code>.
 *
 * @author Ben Alex
 */
public class InsecureChannelProcessor implements InitializingBean, ChannelProcessor {

	/**
	 * 通过使用HTTP重新尝试原始请求
	 */
	private ChannelEntryPoint entryPoint = new RetryWithHttpEntryPoint();

	private String insecureKeyword = "REQUIRES_INSECURE_CHANNEL";

	@Override
	public void afterPropertiesSet() {
		Assert.hasLength(this.insecureKeyword, "insecureKeyword required");
		Assert.notNull(this.entryPoint, "entryPoint required");
	}

	/**
	 * 要求请求不能使用安全协议(如HTTPS)发出
	 * @param invocation
	 * @param config
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config)
			throws IOException, ServletException {
		Assert.isTrue(invocation != null && config != null, "Nulls cannot be provided");
		for (ConfigAttribute attribute : config) {
			if (supports(attribute)) {
				if (invocation.getHttpRequest().isSecure()) {
					this.entryPoint.commence(invocation.getRequest(), invocation.getResponse());
				}
			}
		}
	}

	public ChannelEntryPoint getEntryPoint() {
		return this.entryPoint;
	}

	public String getInsecureKeyword() {
		return this.insecureKeyword;
	}

	public void setEntryPoint(ChannelEntryPoint entryPoint) {
		this.entryPoint = entryPoint;
	}

	public void setInsecureKeyword(String secureKeyword) {
		this.insecureKeyword = secureKeyword;
	}

	/**
	 * 权限表达式必须是 REQUIRES_INSECURE_CHANNEL
	 * @param attribute a configuration attribute that has been configured against the
	 * <tt>ChannelProcessingFilter</tt>.
	 * @return
	 */
	@Override
	public boolean supports(ConfigAttribute attribute) {
		return (attribute != null) && (attribute.getAttribute() != null)
				&& attribute.getAttribute().equals(getInsecureKeyword());
	}

}
