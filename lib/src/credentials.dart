library credentials;

import 'dart:convert';

import 'package:oauth1/oauth1.dart';

/// A class describing OAuth credentials except for client credential
///
/// This class is used to represent **temporary credentials** (also known as an
/// "authorization request") and **token credentials** (also known as an
/// "access token" or "access grant") - two of the three classes
/// of OAuth credentials.
///
/// It is not used for "client credentials", which are represented by
/// [ClientCredentials].
///
class Credentials {
  final String _token;
  final String _tokenSecret;

  Credentials(this._token, this._tokenSecret);
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
