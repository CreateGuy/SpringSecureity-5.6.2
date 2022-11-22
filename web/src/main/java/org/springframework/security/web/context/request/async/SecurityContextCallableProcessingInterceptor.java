/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.context.request.async;

import java.util.concurrent.Callable;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.async.CallableProcessingInterceptor;
import org.springframework.web.context.request.async.CallableProcessingInterceptorAdapter;

/**
 * 为了让异步线程也能获取到安全上下文
 */
public final class SecurityContextCallableProcessingInterceptor extends CallableProcessingInterceptorAdapter {

	private volatile SecurityContext securityContext;

	/**
	 * Create a new {@link SecurityContextCallableProcessingInterceptor} that uses the
	 * {@link SecurityContext} from the {@link SecurityContextHolder} at the time
	 * {@link #beforeConcurrentHandling(NativeWebRequest, Callable)} is invoked.
	 */
	public SecurityContextCallableProcessingInterceptor() {
	}

	/**
	 * Creates a new {@link SecurityContextCallableProcessingInterceptor} with the
	 * specified {@link SecurityContext}.
	 * @param securityContext the {@link SecurityContext} to set on the
	 * {@link SecurityContextHolder} in {@link #preProcess(NativeWebRequest, Callable)}.
	 * Cannot be null.
	 * @throws IllegalArgumentException if {@link SecurityContext} is null.
	 */
	public SecurityContextCallableProcessingInterceptor(SecurityContext securityContext) {
		Assert.notNull(securityContext, "securityContext cannot be null");
		setSecurityContext(securityContext);
	}

	/**
	 * 在执行异步任务之前执行，也就是还是用户线程的时候执行，是为了将安全上下文保存起来
	 * @param request
	 * @param task
	 * @param <T>
	 */
	@Override
	public <T> void beforeConcurrentHandling(NativeWebRequest request, Callable<T> task) {
		if (this.securityContext == null) {
			setSecurityContext(SecurityContextHolder.getContext());
		}
	}

	/**
	 * 在已经执行异步任务(submit)但是还没有执行Callable.call()方法，是为了将安全上下文保存到线程级别的安全上下文策略中
	 * @param request
	 * @param task
	 * @param <T>
	 */
	@Override
	public <T> void preProcess(NativeWebRequest request, Callable<T> task) {
		SecurityContextHolder.setContext(this.securityContext);
	}

	/**
	 * 异步任务已经执行完毕，是为了情况安全上下文
	 * @param request
	 * @param task
	 * @param concurrentResult
	 * @param <T>
	 */
	@Override
	public <T> void postProcess(NativeWebRequest request, Callable<T> task, Object concurrentResult) {
		SecurityContextHolder.clearContext();
	}

	private void setSecurityContext(SecurityContext securityContext) {
		this.securityContext = securityContext;
	}

}
