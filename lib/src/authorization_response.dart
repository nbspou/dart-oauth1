library authorization_response;

import 'credentials.dart';

/// A class describing Response of Authorization response.
///
/// The identifier and shared-secret are stored in the [credentials] and
/// any other parameters are stored in the [optionalParameters].
///
/// This is used to represent the _temporary credential_ from the HTTP response
/// produced by the Temporary Credential Request endpoint; as well as the
/// _token credential_ from the HTTP response produced by the Token Request
/// endpoint.

class AuthorizationResponse {
  final Credentials _credentials;
  final Map<String, String> _optionalParameters;

  AuthorizationResponse(this._credentials, this._optionalParameters);

  factory AuthorizationResponse.fromMap(Map<String, String> parameters) {
    final Map<String, String> paramsCopy = Map<String, String>.from(parameters);
    final Credentials cred = Credentials.fromMap(paramsCopy);
    paramsCopy.remove('oauth_token');
    paramsCopy.remove('oauth_token_secret');
    return AuthorizationResponse(cred, paramsCopy);
  }

  Credentials get credentials => _credentials;
  Map<String, String> get optionalParameters => _optionalParameters;
}
