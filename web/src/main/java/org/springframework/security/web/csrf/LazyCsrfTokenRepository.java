/*
 * Copyright 2012-2016 the original author or authors.
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

package org.springframework.security.web.csrf;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;

/**
 * 懒惰机制的 {@link CsrfTokenRepository}，通常情况下是借助 {@link HttpSessionCsrfTokenRepository}
 */
public final class LazyCsrfTokenRepository implements CsrfTokenRepository {

	/**
	 * The {@link HttpServletRequest} attribute name that the {@link HttpServletResponse}
	 * must be on.
	 */
	private static final String HTTP_RESPONSE_ATTR = HttpServletResponse.class.getName();

	/**
	 * 真正的存储策略
	 */
	private final CsrfTokenRepository delegate;

	/**
	 * Creates a new instance
	 * @param delegate the {@link CsrfTokenRepository} to use. Cannot be null
	 * @throws IllegalArgumentException if delegate is null.
	 */
	public LazyCsrfTokenRepository(CsrfTokenRepository delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	/**
	 * Generates a new token
	 * @param request the {@link HttpServletRequest} to use. The
	 * {@link HttpServletRequest} must have the {@link HttpServletResponse} as an
	 * attribute with the name of <code>HttpServletResponse.class.getName()</code>
	 */
	@Override
	public CsrfToken generateToken(HttpServletRequest request) {
		return wrap(request, this.delegate.generateToken(request));
	}

	/**
	 * 如果{@code CsrfToken}不为空，则不执行任何操作
	 * <p>只有当从执行 CsrfToken.getToken()时，才会进行保存</p>
	 * <p>也是懒机制的体现，只有在最后比较token的时候才生成</p>
	 */
	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		if (token == null) {
			this.delegate.saveToken(token, request, response);
		}
	}

	/**
	 * Delegates to the injected {@link CsrfTokenRepository}
	 */
	@Override
	public CsrfToken loadToken(HttpServletRequest request) {
		return this.delegate.loadToken(request);
	}

	private CsrfToken wrap(HttpServletRequest request, CsrfToken token) {
		HttpServletResponse response = getResponse(request);
		return new SaveOnAccessCsrfToken(this.delegate, request, response, token);
	}

	private HttpServletResponse getResponse(HttpServletRequest request) {
		HttpServletResponse response = (HttpServletResponse) request.getAttribute(HTTP_RESPONSE_ATTR);
		Assert.notNull(response, () -> "The HttpServletRequest attribute must contain an HttpServletResponse "
				+ "for the attribute " + HTTP_RESPONSE_ATTR);
		return response;
	}

	/**
	 * 体现懒机制的令牌，只有在最后要匹配的时候，才会生成令牌
	 */
	private static final class SaveOnAccessCsrfToken implements CsrfToken {

		/**
		 * 存储策略
		 */
		private transient CsrfTokenRepository tokenRepository;

		private transient HttpServletRequest request;

		private transient HttpServletResponse response;

		private final CsrfToken delegate;

		SaveOnAccessCsrfToken(CsrfTokenRepository tokenRepository, HttpServletRequest request,
				HttpServletResponse response, CsrfToken delegate) {
			this.tokenRepository = tokenRepository;
			this.request = request;
			this.response = response;
			this.delegate = delegate;
		}

		@Override
		public String getHeaderName() {
			return this.delegate.getHeaderName();
		}

		@Override
		public String getParameterName() {
			return this.delegate.getParameterName();
		}

		@Override
		public String getToken() {
			// 生成令牌
			saveTokenIfNecessary();
			return this.delegate.getToken();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null || getClass() != obj.getClass()) {
				return false;
			}
			SaveOnAccessCsrfToken other = (SaveOnAccessCsrfToken) obj;
			if (this.delegate == null) {
				if (other.delegate != null) {
					return false;
				}
			}
			else if (!this.delegate.equals(other.delegate)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((this.delegate == null) ? 0 : this.delegate.hashCode());
			return result;
		}

		@Override
		public String toString() {
			return "SaveOnAccessCsrfToken [delegate=" + this.delegate + "]";
		}

		/**
		 * 生成令牌
		 */
		private void saveTokenIfNecessary() {
			if (this.tokenRepository == null) {
				return;
			}
			synchronized (this) {
				if (this.tokenRepository != null) {
					// 调用真正的存储策略，生成令牌
					this.tokenRepository.saveToken(this.delegate, this.request, this.response);
					// 防止第二次生成
					this.tokenRepository = null;
					this.request = null;
					this.response = null;
				}
			}
		}

	}

}
