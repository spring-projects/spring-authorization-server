/*
 * Copyright 2020-2021 the original author or authors.
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
package org.springframework.security.config.util;

import org.assertj.core.util.Throwables;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;

import java.util.ArrayList;
import java.util.List;

/**
 * Hamcrest matcher that records matched values
 *
 * @author Rafal Lewczuk
 * @since 0.2.1
 * @param <T>
 */
public class ValueCaptureMatcher<T> extends BaseMatcher<T> {

	private ClassCastException castException;
	private List<T> values = new ArrayList<>();

	public T lastValue() {
		return values.isEmpty() ? null : values.get(values.size()-1);
	}

	public List<T> getValues() {
		return values;
	}

	@Override
	public boolean matches(Object item) {
		try {
			values.add((T) item);
		} catch (ClassCastException e) {
			castException = e;
			return false;
		}
		return true;
	}

	@Override
	public void describeTo(Description description) {
		if (castException != null) {
			description.appendText("ClassCastException with message: ");
			description.appendText(castException.getMessage());
			description.appendText(String.format("%n%nStacktrace was: "));
			description.appendText(Throwables.getStackTrace(castException));
		}
	}
}
