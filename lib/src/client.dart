library oauth1_client;

import 'dart:async';
import 'package:http/http.dart' as http;
import 'package:oauth1/oauth1.dart';

import 'signature_method.dart';
import 'client_credentials.dart';
import 'credentials.dart';

/// A proxy class describing OAuth 1.0 Authenticated Request
///
/// http://tools.ietf.org/html/rfc5849#section-3
///
/// If _credentials is null, this is usable for authorization requests too.

class Client extends http.BaseClient {
  final SignatureMethod _signatureMethod;
  final ClientCredentials _clientCredentials;
  final Credentials _credentials;
  final http.BaseClient _httpClient;

  /// A constructor of Client.
  ///
  /// If you want to use in web browser, pass http.BrowserClient object for httpClient.
  /// https://api.dartlang.org/apidocs/channels/stable/dartdoc-viewer/http/http-browser_client.BrowserClient
  Client(this._signatureMethod, this._clientCredentials, this._credentials,
      [http.BaseClient httpClient])
      : _httpClient = httpClient != null ? httpClient : http.Client();

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    final AuthorizationRequest auth = AuthorizationRequest();

    auth.set(AuthorizationRequest.oauth_version,
        AuthorizationRequest.supportedVersion);

    // Include additional parameters, from any Authorization header and
    // any www-form-urlencoded body, so they are also signed as required by
    // RFC 5849.

    final Map<String, String> headers = request.headers;

    if (headers.containsKey('Authorization')) {
      final String str = headers['Authorization'];
      Uri.splitQueryString(str).forEach((String k, String v) => auth.add(k, v));
    }
    if (headers.containsKey('content-type') &&
        headers['content-type'].contains('application/x-www-form-urlencoded') &&
        (request as http.Request).body != null) {
      final String str = (request as http.Request).body;
      Uri.splitQueryString(str).forEach((String k, String v) => auth.add(k, v));
    }

    // Sign it and include it as an authorization header

    auth.sign(request.method, request.url, _clientCredentials, _signatureMethod,
        tokenCredentials: _credentials);

    request.headers['Authorization'] = auth.headerValue();
    return _httpClient.send(request);
  }
}
