/*
 * Copyright 2020-2023 the original author or authors.
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
package sample.web;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
@ControllerAdvice
public class DeviceControllerAdvice {

	private static final Set<String> DEVICE_GRANT_ERRORS = new HashSet<>(Arrays.asList(
			"authorization_pending",
			"slow_down",
			"access_denied",
			"expired_token"
	));

	@ExceptionHandler(OAuth2AuthorizationException.class)
	public ResponseEntity<OAuth2Error> handleError(OAuth2AuthorizationException ex) {
		String errorCode = ex.getError().getErrorCode();
		if (DEVICE_GRANT_ERRORS.contains(errorCode)) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getError());
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getError());
	}

}
