library authorization;

import 'dart:async';
import 'package:http/http.dart' as http;
import 'package:oauth1/oauth1.dart';

import 'credentials.dart';
import 'client_credentials.dart';
import 'platform.dart';
import 'authorization_response.dart';

/// A proxy class describing OAuth 1.0 redirection-based authorization.
/// http://tools.ietf.org/html/rfc5849#section-2
///
/// Redirection works are responded to client.
/// So you can do PIN-based authorization too if you want.
class Authorization {
  final ClientCredentials _clientCredentials;
  final Platform _platform;
  final http.BaseClient _httpClient;

  /// A constructor of Authorization.
  ///
  /// If you want to use in web browser, pass http.BrowserClient object for httpClient.
  /// https://api.dartlang.org/apidocs/channels/stable/dartdoc-viewer/http/http-browser_client.BrowserClient
  Authorization(this._clientCredentials, this._platform,
      [http.BaseClient httpClient])
      : _httpClient = httpClient != null ? httpClient : http.Client();

  /// Obtain a set of temporary credentials from the server.
  /// http://tools.ietf.org/html/rfc5849#section-2.1
  ///
  /// The [callbackURI] is optional. If provided, it must be a URI for the
  /// callback's endpoint, or the value must be "oob" (case significant)
  /// indicating the verifier will be communicated to the client via an
  /// out-of-band mechanism. If the _callBackURI_ is omitted, it defaults to
  /// "oob", which usually means the server shows the resource owner a PIN
  /// to manually enter into the client.

  Future<AuthorizationResponse> requestTemporaryCredentials(
      [String callbackURI]) async {
    // TODO: allow optional parameters to be included in the request
    // Since section 2.1 of RFC5849 says "servers MAY specify additional
    // parameters".

    final AuthorizationHeader auth = AuthorizationHeader.empty();
    auth[AuthorizationHeader.oauth_version] = AuthorizationHeader.version;
    auth[AuthorizationHeader.oauth_callback] = callbackURI ?? 'oob';

    auth.sign('POST', _platform.temporaryCredentialsRequestURI,
        _clientCredentials, _platform.signatureMethod);

    final http.Response res = await _httpClient.post(
        _platform.temporaryCredentialsRequestURI,
        headers: <String, String>{'Authorization': auth.headerValue()});

    if (res.statusCode != 200) {
      throw StateError(res.body);
    }

    final Map<String, String> params = Uri.splitQueryString(res.body);
    if (params['oauth_callback_confirmed'].toLowerCase() != 'true') {
      // Note: this is probably more forgiving that the specification intended.
      // The specification does not say "TRUE" is permitted as a response.
      throw StateError('oauth_callback_confirmed must be "true"');
    }

    return AuthorizationResponse.fromMap(params);
  }

  /// Get resource owner authorization URI.
  /// http://tools.ietf.org/html/rfc5849#section-2.2
  String getResourceOwnerAuthorizationURI(
      String temporaryCredentialsIdentifier) {
    return _platform.resourceOwnerAuthorizationURI +
        '?oauth_token=' +
        Uri.encodeComponent(temporaryCredentialsIdentifier);
  }

  /// Obtain a set of token credentials from the server.
  /// http://tools.ietf.org/html/rfc5849#section-2.3
  Future<AuthorizationResponse> requestTokenCredentials(
      Credentials tokenCredentials, String verifier) async {
    final AuthorizationHeader auth = AuthorizationHeader.empty();
    auth[AuthorizationHeader.oauth_version] = '1.0';
    auth[AuthorizationHeader.oauth_verifier] = verifier;

    auth.sign('POST', _platform.tokenCredentialsRequestURI, _clientCredentials,
        _platform.signatureMethod,
        tokenCredentials: tokenCredentials);

    final http.Response res = await _httpClient.post(
        _platform.tokenCredentialsRequestURI,
        headers: <String, String>{'Authorization': auth.headerValue()});

    if (res.statusCode != 200) {
      throw StateError(res.body);
    }
    final Map<String, String> params = Uri.splitQueryString(res.body);
    return AuthorizationResponse.fromMap(params);
  }
}
