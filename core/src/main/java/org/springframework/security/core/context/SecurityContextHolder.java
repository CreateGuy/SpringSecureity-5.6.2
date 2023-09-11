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

package org.springframework.security.core.context;

import java.lang.reflect.Constructor;

import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;

/**
 * 操作线程级别的安全上下文帮助类
 */
public class SecurityContextHolder {

	/**
	 * 下面这四个都是为了比较然后使用某种策略
	 */
	public static final String MODE_THREADLOCAL = "MODE_THREADLOCAL";

	public static final String MODE_INHERITABLETHREADLOCAL = "MODE_INHERITABLETHREADLOCAL";

	public static final String MODE_GLOBAL = "MODE_GLOBAL";

	private static final String MODE_PRE_INITIALIZED = "MODE_PRE_INITIALIZED";

	public static final String SYSTEM_PROPERTY = "spring.security.strategy";

	/**
	 * 获得指定的系统变量，是线程级别安全上下文存储策略
	 */
	private static String strategyName = System.getProperty(SYSTEM_PROPERTY);

	/**
	 * 线程级别安全上下文的策略
	 */
	private static SecurityContextHolderStrategy strategy;

	/**
	 * 初始化次数，没懂应用场景
	 */
	private static int initializeCount = 0;

	/**
	 * 当前类被加载-连接-初始化的阶段执行
	 */
	static {
		initialize();
	}

	private static void initialize() {
		initializeStrategy();
		initializeCount++;
	}

	/**
	 * 初始化线程级别的安全上下文的存储策略
	 */
	private static void initializeStrategy() {
		if (MODE_PRE_INITIALIZED.equals(strategyName)) {
			Assert.state(strategy != null, "When using " + MODE_PRE_INITIALIZED
					+ ", setContextHolderStrategy must be called with the fully constructed strategy");
			return;
		}
		//如果没有设置过使用的策略，就默认使用ThreadLocal作为存储策略
		if (!StringUtils.hasText(strategyName)) {
			// Set default
			strategyName = MODE_THREADLOCAL;
		}
		//使用ThreadLocal作为线程级别安全上下文存储策略
		if (strategyName.equals(MODE_THREADLOCAL)) {
			strategy = new ThreadLocalSecurityContextHolderStrategy();
			return;
		}
		//使用InheritableThreadLocal作为线程级别安全上下文存储策略
		if (strategyName.equals(MODE_INHERITABLETHREADLOCAL)) {
			strategy = new InheritableThreadLocalSecurityContextHolderStrategy();
			return;
		}
		//使用Global作为线程级别安全上下文存储策略
		if (strategyName.equals(MODE_GLOBAL)) {
			strategy = new GlobalSecurityContextHolderStrategy();
			return;
		}
		//尝试加载自定义的线程级别安全上下文存储策略
		try {
			Class<?> clazz = Class.forName(strategyName);
			Constructor<?> customStrategy = clazz.getConstructor();
			strategy = (SecurityContextHolderStrategy) customStrategy.newInstance();
		}
		catch (Exception ex) {
			ReflectionUtils.handleReflectionException(ex);
		}
	}

	/**
	 * 清空当前线程的安全上下文
	 */
	public static void clearContext() {
		strategy.clearContext();
	}

	/**
	 * 获得当前线程存储的安全上下文
	 * @return
	 */
	public static SecurityContext getContext() {
		return strategy.getContext();
	}

	/**
	 * Primarily for troubleshooting purposes, this method shows how many times the class
	 * has re-initialized its <code>SecurityContextHolderStrategy</code>.
	 * @return the count (should be one unless you've called
	 * {@link #setStrategyName(String)} or
	 * {@link #setContextHolderStrategy(SecurityContextHolderStrategy)} to switch to an
	 * alternate strategy).
	 */
	public static int getInitializeCount() {
		return initializeCount;
	}

	/**
	 * 为当前线程保存安全上下文对象
	 */
	public static void setContext(SecurityContext context) {
		strategy.setContext(context);
	}

	/**
	 * 改变线程级别的安全上下文存储策略
	 * 这有可能影响到以前保存的
	 */
	public static void setStrategyName(String strategyName) {
		SecurityContextHolder.strategyName = strategyName;
		initialize();
	}

	/**
	 * Use this {@link SecurityContextHolderStrategy}.
	 *
	 * Call either {@link #setStrategyName(String)} or this method, but not both.
	 *
	 * This method is not thread safe. Changing the strategy while requests are in-flight
	 * may cause race conditions.
	 *
	 * {@link SecurityContextHolder} maintains a static reference to the provided
	 * {@link SecurityContextHolderStrategy}. This means that the strategy and its members
	 * will not be garbage collected until you remove your strategy.
	 *
	 * To ensure garbage collection, remember the original strategy like so:
	 *
	 * <pre>
	 *     SecurityContextHolderStrategy original = SecurityContextHolder.getContextHolderStrategy();
	 *     SecurityContextHolder.setContextHolderStrategy(myStrategy);
	 * </pre>
	 *
	 * And then when you are ready for {@code myStrategy} to be garbage collected you can
	 * do:
	 *
	 * <pre>
	 *     SecurityContextHolder.setContextHolderStrategy(original);
	 * </pre>
	 * @param strategy the {@link SecurityContextHolderStrategy} to use
	 * @since 5.6
	 */
	public static void setContextHolderStrategy(SecurityContextHolderStrategy strategy) {
		Assert.notNull(strategy, "securityContextHolderStrategy cannot be null");
		SecurityContextHolder.strategyName = MODE_PRE_INITIALIZED;
		SecurityContextHolder.strategy = strategy;
		initialize();
	}

	/**
	 * Allows retrieval of the context strategy. See SEC-1188.
	 * @return the configured strategy for storing the security context.
	 */
	public static SecurityContextHolderStrategy getContextHolderStrategy() {
		return strategy;
	}

	/**
	 * 为当前线程创建一个空安全上下文，并保存起来
	 */
	public static SecurityContext createEmptyContext() {
		return strategy.createEmptyContext();
	}

	@Override
	public String toString() {
		return "SecurityContextHolder[strategy='" + strategy.getClass().getSimpleName() + "'; initializeCount="
				+ initializeCount + "]";
	}

}
