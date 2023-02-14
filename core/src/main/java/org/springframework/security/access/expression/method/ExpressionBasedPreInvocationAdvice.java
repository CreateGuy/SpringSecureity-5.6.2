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

package org.springframework.security.access.expression.method;

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * 在方法执行前进行参数过滤和权限判断
 */
public class ExpressionBasedPreInvocationAdvice implements PreInvocationAuthorizationAdvice {

	private MethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();

	@Override
	public boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute attr) {
		PreInvocationExpressionAttribute preAttr = (PreInvocationExpressionAttribute) attr;
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, mi);

		// 参数过滤表达式
		Expression preFilter = preAttr.getFilterExpression();
		// 方法执行前的权限表达式
		Expression preAuthorize = preAttr.getAuthorizeExpression();

		// 进行参数过滤
		if (preFilter != null) {
			// 找到需要过滤的参数
			Object filterTarget = findFilterTarget(preAttr.getFilterTarget(), ctx, mi);
			// 进行过滤
			this.expressionHandler.filter(filterTarget, preFilter, ctx);
		}

		// 匹配权限表达式
		return (preAuthorize != null) ? ExpressionUtils.evaluateAsBoolean(preAuthorize, ctx) : true;
	}

	/**
	 * 找到需要过滤的参数
	 * @param filterTargetName 要过滤的集合
	 * @param ctx
	 * @param invocation
	 * @return
	 */
	private Object findFilterTarget(String filterTargetName, EvaluationContext ctx, MethodInvocation invocation) {
		Object filterTarget = null;

		// 通过名称查询
		if (filterTargetName.length() > 0) {
			// 查找指定参数
			filterTarget = ctx.lookupVariable(filterTargetName);
			Assert.notNull(filterTarget,
					() -> "Filter target was null, or no argument with name " + filterTargetName + " found in method");
		}
		// 如果参数列表中只有一个参数，那么就获得第一个参数
		else if (invocation.getArguments().length == 1) {
			Object arg = invocation.getArguments()[0];
			// @PreFilter只支持带有删除功能的数组或集合
			if (arg.getClass().isArray() || arg instanceof Collection<?>) {
				filterTarget = arg;
			}
			Assert.notNull(filterTarget, () -> "A PreFilter expression was set but the method argument type"
					+ arg.getClass() + " is not filterable");
		}
		// 无法确定筛选的方法参数
		else if (invocation.getArguments().length > 1) {
			throw new IllegalArgumentException(
					"Unable to determine the method argument for filtering. Specify the filter target.");
		}
		Assert.isTrue(!filterTarget.getClass().isArray(),
				"Pre-filtering on array types is not supported. Using a Collection will solve this problem");
		return filterTarget;
	}

	public void setExpressionHandler(MethodSecurityExpressionHandler expressionHandler) {
		this.expressionHandler = expressionHandler;
	}

}
