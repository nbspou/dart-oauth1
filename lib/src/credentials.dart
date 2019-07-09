library credentials;

import 'dart:convert';

import 'package:oauth1/oauth1.dart';

/// Temporary credentials or token credentials.
///
/// This class is used to represent _temporary credentials_ (also known as an
/// "authorization request") and _token credentials_ (also known as an
/// "access token" or "access grant").
///
/// The third type of OAuth credentials, _client credentials_, are not
/// represented by this class, but by the [ClientCredentials] class.

class Credentials {
  final String _token;
  final String _tokenSecret;

  const Credentials(this._token, this._tokenSecret);
  factory Credentials.fromMap(Map<String, String> parameters) {
    if (!parameters.containsKey('oauth_token')) {
      throw ArgumentError("params doesn't have a key 'oauth_token'");
    }
    if (!parameters.containsKey('oauth_token_secret')) {
      throw ArgumentError("params doesn't have a key 'oauth_token_secret'");
    }
    return Credentials(
        parameters['oauth_token'], parameters['oauth_token_secret']);
  }
  factory Credentials.fromJSON(String jstr) {
    return Credentials.fromMap(json.decode(jstr));
  }

  String get token => _token;
  String get tokenSecret => _tokenSecret;

  @override
  String toString() {
    return 'oauth_token=$token&oauth_token_secret=$tokenSecret';
  }

  Map<String, dynamic> toJSON() {
    return <String, dynamic>{
      'oauth_token': token,
      'oauth_token_secret': tokenSecret
    };
  }
}
