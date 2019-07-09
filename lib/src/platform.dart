library platform;

import 'signature_method.dart';

/// Configuration of OAuth1Authorization.
///
/// http://tools.ietf.org/html/rfc5849

class Platform {
  final String _temporaryCredentialsRequestURI;
  final String _resourceOwnerAuthorizationURI;
  final String _tokenCredentialsRequestURI;
  final SignatureMethod _signatureMethod;

  Platform(
      this._temporaryCredentialsRequestURI,
      this._resourceOwnerAuthorizationURI,
      this._tokenCredentialsRequestURI,
      this._signatureMethod);

  /// Temporary Credentials Request URI
  /// http://tools.ietf.org/html/rfc5849#section-2.1
  String get temporaryCredentialsRequestURI => _temporaryCredentialsRequestURI;

  /// Resource Owner Authorization URI
  /// http://tools.ietf.org/html/rfc5849#section-2.2
  String get resourceOwnerAuthorizationURI => _resourceOwnerAuthorizationURI;

  /// Token Credentials Request URI
  /// http://tools.ietf.org/html/rfc5849#section-2.3
  String get tokenCredentialsRequestURI => _tokenCredentialsRequestURI;

  /// Signature Method
  /// http://tools.ietf.org/html/rfc5849#section-3.4
  SignatureMethod get signatureMethod => _signatureMethod;
}
