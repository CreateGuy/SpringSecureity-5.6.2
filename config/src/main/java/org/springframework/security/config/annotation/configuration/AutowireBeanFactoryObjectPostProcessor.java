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

package org.springframework.security.config.annotation.configuration;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.Aware;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.config.AutowireCapableBeanFactory;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.util.Assert;

/**
 * Spring Security会通过new创建很多bean，
 * 让这些由SpringSecurity创建的bean也和跟spring容器中的bean有同样的生命周期
 */
final class AutowireBeanFactoryObjectPostProcessor
		implements ObjectPostProcessor<Object>, DisposableBean, SmartInitializingSingleton {

	private final Log logger = LogFactory.getLog(getClass());

	private final AutowireCapableBeanFactory autowireBeanFactory;

	private final List<DisposableBean> disposableBeans = new ArrayList<>();

	private final List<SmartInitializingSingleton> smartSingletons = new ArrayList<>();

	AutowireBeanFactoryObjectPostProcessor(AutowireCapableBeanFactory autowireBeanFactory) {
		Assert.notNull(autowireBeanFactory, "autowireBeanFactory cannot be null");
		this.autowireBeanFactory = autowireBeanFactory;
	}

	/**
	 * 让这些由SpringSecurity创建的bean也和跟spring容器中的bean有同样的生命周期，也能注入相应的依赖，从而进入准备好被使用的状态
	 * @param object the object to initialize
	 * @param <T>
	 * @return
	 */
	@Override
	@SuppressWarnings("unchecked")
	public <T> T postProcess(T object) {
		if (object == null) {
			return null;
		}
		T result = null;
		try {
			//进行初始化
			result = (T) this.autowireBeanFactory.initializeBean(object, object.toString());
		}
		catch (RuntimeException ex) {
			Class<?> type = object.getClass();
			throw new RuntimeException("Could not postProcess " + object + " of type " + type, ex);
		}
		//进行自动装配属性
		this.autowireBeanFactory.autowireBean(object);
		if (result instanceof DisposableBean) {
			this.disposableBeans.add((DisposableBean) result);
		}
		if (result instanceof SmartInitializingSingleton) {
			this.smartSingletons.add((SmartInitializingSingleton) result);
		}
		return result;
	}

	@Override
	public void afterSingletonsInstantiated() {
		for (SmartInitializingSingleton singleton : this.smartSingletons) {
			singleton.afterSingletonsInstantiated();
		}
	}

	@Override
	public void destroy() {
		for (DisposableBean disposable : this.disposableBeans) {
			try {
				disposable.destroy();
			}
			catch (Exception ex) {
				this.logger.error(ex);
			}
		}
	}

}
