package org.springframework.security.oauth2.server.authorization.web;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;

/**
 * @author shanhy
 * @date 2021/3/30 15:42
 */
public interface UserConsentPage {

	MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);
	String CONSENT_ACTION_PARAMETER_NAME = "consent_action";
	String CONSENT_ACTION_APPROVE = "approve";
	String CONSENT_ACTION_CANCEL = "cancel";

	default void displayConsent(HttpServletRequest request, HttpServletResponse response,
			RegisteredClient registeredClient, OAuth2Authorization authorization) throws IOException {

		String consentPage = generateConsentPage(request, registeredClient, authorization);
		response.setContentType(TEXT_HTML_UTF8.toString());
		response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
		response.getWriter().write(consentPage);
	}

	default boolean isConsentApproved(HttpServletRequest request) {
		return CONSENT_ACTION_APPROVE.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	default boolean isConsentCancelled(HttpServletRequest request) {
		return CONSENT_ACTION_CANCEL.equalsIgnoreCase(request.getParameter(CONSENT_ACTION_PARAMETER_NAME));
	}

	default String generateConsentPage(HttpServletRequest request,
			RegisteredClient registeredClient, OAuth2Authorization authorization) {

		OAuth2AuthorizationRequest authorizationRequest = authorization.getAttribute(
				OAuth2AuthorizationRequest.class.getName());
		Set<String> scopes = new HashSet<>(authorizationRequest.getScopes());
		scopes.remove(OidcScopes.OPENID);		// openid scope does not require consent
		String state = authorization.getAttribute(
				OAuth2ParameterNames.STATE);

		StringBuilder builder = new StringBuilder();

		builder.append("<!DOCTYPE html>");
		builder.append("<html lang=\"en\">");
		builder.append("<head>");
		builder.append("    <meta charset=\"utf-8\">");
		builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
		builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
		builder.append("    <title>Consent required</title>");
		builder.append("</head>");
		builder.append("<body>");
		builder.append("<div class=\"container\">");
		builder.append("    <div class=\"py-5\">");
		builder.append("        <h1 class=\"text-center\">Consent required</h1>");
		builder.append("    </div>");
		builder.append("    <div class=\"row\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p><span class=\"font-weight-bold text-primary\">" + registeredClient.getClientId() + "</span> wants to access your account <span class=\"font-weight-bold\">" + authorization.getPrincipalName() + "</span></p>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("    <div class=\"row pb-3\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p>The following permissions are requested by the above app.<br/>Please review these and consent if you approve.</p>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("    <div class=\"row\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <form method=\"post\" action=\"" + request.getRequestURI() + "\">");
		builder.append("                <input type=\"hidden\" name=\"client_id\" value=\"" + registeredClient.getClientId() + "\">");
		builder.append("                <input type=\"hidden\" name=\"state\" value=\"" + state + "\">");

		for (String scope : scopes) {
			builder.append("                <div class=\"form-group form-check py-1\">");
			builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"" + scope + "\" id=\"" + scope + "\" checked>");
			builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
			builder.append("                </div>");
		}

		builder.append("                <div class=\"form-group pt-3\">");
		builder.append("                    <button class=\"btn btn-primary btn-lg\" type=\"submit\" name=\"consent_action\" value=\"approve\">Submit Consent</button>");
		builder.append("                </div>");
		builder.append("                <div class=\"form-group\">");
		builder.append("                    <button class=\"btn btn-link regular\" type=\"submit\" name=\"consent_action\" value=\"cancel\">Cancel</button>");
		builder.append("                </div>");
		builder.append("            </form>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("    <div class=\"row pt-4\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p><small>Your consent to provide access is required.<br/>If you do not approve, click Cancel, in which case no information will be shared with the app.</small></p>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("</div>");
		builder.append("</body>");
		builder.append("</html>");

		return builder.toString();
	}

}
