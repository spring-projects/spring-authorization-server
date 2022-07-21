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
package sample.controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
/**
 * @author kuan shu
 * @since 0.3.1
 */
@Controller
public class ResourceController {
	@RequestMapping("/secured-page")
	public String securedPage(Model model){
		String authenticatedUser = SecurityContextHolder.getContext().getAuthentication().getName();
		model.addAttribute("username",authenticatedUser);
		return "secured-page";
	}

	@RequestMapping("/public-page")
	public String publicPage(){
		return "public-page";
	}
}
