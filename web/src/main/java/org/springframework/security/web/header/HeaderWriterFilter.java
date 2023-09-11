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

package org.springframework.security.web.header;

import java.io.IOException;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.util.OnCommittedResponseWrapper;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 向响应头写入消息
 * 比如：添加启用浏览器保护的某些头是很有用的。比如X-Frame-Options, X-XSS-Protection和X-Content-Type-Options。
 */
public class HeaderWriterFilter extends OncePerRequestFilter {

	/**
	 * 头部写入器
	 */
	private final List<HeaderWriter> headerWriters;

	/**
	 * 是否在请求的开始就写入请求头
	 */
	private boolean shouldWriteHeadersEagerly = false;

	/**
	 * Creates a new instance.
	 * @param headerWriters the {@link HeaderWriter} instances to write out headers to the
	 * {@link HttpServletResponse}.
	 */
	public HeaderWriterFilter(List<HeaderWriter> headerWriters) {
		Assert.notEmpty(headerWriters, "headerWriters cannot be null or empty");
		this.headerWriters = headerWriters;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		//是否在请求的开始就写头
		if (this.shouldWriteHeadersEagerly) {
			doHeadersBefore(request, response, filterChain);
		}
		else {
			doHeadersAfter(request, response, filterChain);
		}
	}

	/**
	 * 在请求开始就往响应消息写响应头
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doHeadersBefore(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		writeHeaders(request, response);
		filterChain.doFilter(request, response);
	}

	/**
	 * 在请求结束后才往响应消息写响应头
	 * @param request
	 * @param response
	 * @param filterChain
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doHeadersAfter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		//将response包装为HeaderWriterResponse是为了在执行过程中就可以进行头部写入
		HeaderWriterResponse headerWriterResponse = new HeaderWriterResponse(request, response);
		HeaderWriterRequest headerWriterRequest = new HeaderWriterRequest(request, headerWriterResponse);
		try {
			filterChain.doFilter(headerWriterRequest, headerWriterResponse);
		}
		finally {
			headerWriterResponse.writeHeaders();
		}
	}

	void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		for (HeaderWriter writer : this.headerWriters) {
			writer.writeHeaders(request, response);
		}
	}

	/**
	 * Allow writing headers at the beginning of the request.
	 * @param shouldWriteHeadersEagerly boolean to allow writing headers at the beginning
	 * of the request.
	 * @since 5.2
	 */
	public void setShouldWriteHeadersEagerly(boolean shouldWriteHeadersEagerly) {
		this.shouldWriteHeadersEagerly = shouldWriteHeadersEagerly;
	}

	/**
	 * 对Response进行包装，其目的是为了在请求在执行过程中就可以进行头部写入
	 */
	class HeaderWriterResponse extends OnCommittedResponseWrapper {

		private final HttpServletRequest request;

		HeaderWriterResponse(HttpServletRequest request, HttpServletResponse response) {
			super(response);
			this.request = request;
		}

		/**
		 * 此方法可以直接调用
		 * 比如说Controller中执行response.(include,sendError, redirect, flushBuffer)的时候，此方法就会执行
		 */
		@Override
		protected void onResponseCommitted() {
			writeHeaders();
			this.disableOnResponseCommitted();
		}

		protected void writeHeaders() {
			if (isDisableOnResponseCommitted()) {
				return;
			}
			HeaderWriterFilter.this.writeHeaders(this.request, getHttpResponse());
		}

		private HttpServletResponse getHttpResponse() {
			return (HttpServletResponse) getResponse();
		}

	}

	static class HeaderWriterRequest extends HttpServletRequestWrapper {

		private final HeaderWriterResponse response;

		HeaderWriterRequest(HttpServletRequest request, HeaderWriterResponse response) {
			super(request);
			this.response = response;
		}

		@Override
		public RequestDispatcher getRequestDispatcher(String path) {
			return new HeaderWriterRequestDispatcher(super.getRequestDispatcher(path), this.response);
		}

	}

	static class HeaderWriterRequestDispatcher implements RequestDispatcher {

		private final RequestDispatcher delegate;

		private final HeaderWriterResponse response;

		HeaderWriterRequestDispatcher(RequestDispatcher delegate, HeaderWriterResponse response) {
			this.delegate = delegate;
			this.response = response;
		}

		@Override
		public void forward(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			this.delegate.forward(request, response);
		}

		@Override
		public void include(ServletRequest request, ServletResponse response) throws ServletException, IOException {
			this.response.onResponseCommitted();
			this.delegate.include(request, response);
		}

	}

}
