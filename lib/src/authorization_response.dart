library authorization_response;

import 'credentials.dart';

/// A class describing Response of Authorization request.
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
