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

package org.springframework.security.web.access;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.WebAttributes;
import org.springframework.util.Assert;

/**
 * 访问被拒绝处理器的默认实现，是为了将请求进行转发到错误页面
 */
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {

	protected static final Log logger = LogFactory.getLog(AccessDeniedHandlerImpl.class);

	/**
	 * 错误页面
	 */
	private String errorPage;

	/**
	 * 为了将请求转发到错误页面
	 * @param request that resulted in an <code>AccessDeniedException</code>
	 * @param response so that the user agent can be advised of the failure
	 * @param accessDeniedException that caused the invocation
	 * @throws IOException
	 * @throws ServletException
	 */
	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		if (response.isCommitted()) {
			logger.trace("Did not write to response since already committed");
			return;
		}
		//没有设置错误页面，就用默认的403
		if (this.errorPage == null) {
			logger.debug("Responding with 403 status code");
			response.sendError(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.getReasonPhrase());
			return;
		}
		//将异常放入请求Attribute中(可能用于视图)
		request.setAttribute(WebAttributes.ACCESS_DENIED_403, accessDeniedException);
		//设置状态码403
		response.setStatus(HttpStatus.FORBIDDEN.value());
		// forward to error page.
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.format("Forwarding to %s with status code 403", this.errorPage));
		}
		//进行转发
		request.getRequestDispatcher(this.errorPage).forward(request, response);
	}

	/**
	 * 设置错误页面。必须以“/”开头
	 * @param errorPage
	 */
	public void setErrorPage(String errorPage) {
		Assert.isTrue(errorPage == null || errorPage.startsWith("/"), "errorPage must begin with '/'");
		this.errorPage = errorPage;
	}

}
