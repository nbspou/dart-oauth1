library oauth1_client;

import 'dart:async';

import 'package:http/http.dart' as http;

import 'authorization_header_builder.dart';
import 'client_credentials.dart';
import 'credentials.dart';
import 'signature_method.dart';

/// A proxy class describing OAuth 1.0 Authenticated Request
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
      [http.BaseClient? httpClient])
      : _httpClient =
            httpClient != null ? httpClient : http.Client() as http.BaseClient;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final AuthorizationHeaderBuilder ahb = AuthorizationHeaderBuilder();
    ahb.signatureMethod = _signatureMethod;
    ahb.clientCredentials = _clientCredentials;
    ahb.credentials = _credentials;
    ahb.method = request.method;
    ahb.url = request.url.toString();
    final Map<String, String> headers = request.headers;
    Map<String, String> additionalParameters = <String, String>{};
    if (headers.containsKey('Authorization')) {
      additionalParameters = Uri.splitQueryString(headers['Authorization']!);
    }
    if (headers.containsKey('content-type') &&
        headers['content-type']!
            .contains('application/x-www-form-urlencoded')) {
      additionalParameters
          .addAll(Uri.splitQueryString((request as http.Request).body));
    }
    ahb.additionalParameters = additionalParameters;

    request.headers['Authorization'] = await ahb.build().encode();
    return await _httpClient.send(request);
  }
}
