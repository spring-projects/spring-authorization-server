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

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.web.servlet.error.ErrorController;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Steve Riesenberg
 * @since 1.1
 */
@Controller
public class DefaultErrorController implements ErrorController {

	@RequestMapping("/error")
	public String handleError(Model model, HttpServletRequest request) {
		String errorMessage = getErrorMessage(request);
		if (errorMessage.startsWith("[access_denied]")) {
			model.addAttribute("errorTitle", "Access Denied");
			model.addAttribute("errorMessage", "You have denied access.");
		} else {
			model.addAttribute("errorTitle", "Error");
			model.addAttribute("errorMessage", errorMessage);
		}
		return "error";
	}

	private String getErrorMessage(HttpServletRequest request) {
		String errorMessage = (String) request.getAttribute(RequestDispatcher.ERROR_MESSAGE);
		return StringUtils.hasText(errorMessage) ? errorMessage : "";
	}

}
