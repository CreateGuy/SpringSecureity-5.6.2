/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.context;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.SmartApplicationListener;
import org.springframework.util.Assert;

/**
 * 用于监听ApplicationEvent事件的代表监听器
 * SessionInformation
 * @author Rob Winch
 */
public final class DelegatingApplicationListener implements ApplicationListener<ApplicationEvent> {

	/**
	 * 真正ApplicationEvent事件进行操作的监听器集合
	 */
	private List<SmartApplicationListener> listeners = new CopyOnWriteArrayList<>();

	@Override
	public void onApplicationEvent(ApplicationEvent event) {
		if (event == null) {
			return;
		}
		for (SmartApplicationListener listener : this.listeners) {
			Object source = event.getSource();
			//判断当前监听器是否支持此事件
			if (source != null && listener.supportsEventType(event.getClass())
					&& listener.supportsSourceType(source.getClass())) {
				listener.onApplicationEvent(event);
			}
		}
	}

	/**
	 * 添加一个监听器
	 * 默认就只有GenericApplicationListenerAdapter会被注册进行来
	 * 而这个GenericApplicationListenerAdapter内部只会有一个{@link org.springframework.security.core.session.SessionRegistryImpl}
	 * @param smartApplicationListener
	 */
	public void addListener(SmartApplicationListener smartApplicationListener) {
		Assert.notNull(smartApplicationListener, "smartApplicationListener cannot be null");
		this.listeners.add(smartApplicationListener);
	}

}
