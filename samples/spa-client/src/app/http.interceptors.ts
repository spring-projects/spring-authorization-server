import {HttpRequest, HttpHandlerFn, HttpEvent} from '@angular/common/http';
import {Observable} from 'rxjs';
import {environment} from "./environment";

/*
IMPORTANT:

By default, the HttpClient passes the CSRF token via the X-XSRF-TOKEN header using its built-in interceptor.
However, this DOES NOT WORK when absolute URLs are used in HttpClient calls.
Hence, the reason for this interceptor, as it prepends the Backend base URL to the relative URL.
Ensure you only use relative URLs in HttpClient calls for mutating requests (e.g. POST),
otherwise operations such as /logout will not work.

See the reference for further information:
https://angular.dev/best-practices/security#httpclient-xsrf-csrf-security
 */

export function withCredentialsInterceptor(request: HttpRequest<unknown>, next: HttpHandlerFn): Observable<HttpEvent<unknown>> {
  request = request.clone({
    url: environment.backendBaseUrl + request.url,
    withCredentials: true   // This is required to ensure the Session Cookie is passed in every request to the Backend
  });
  return next(request);
}
