library client_credentials;

import 'package:pointycastle/asymmetric/api.dart';

/// A class describing OAuth **client credentials**.
///
/// The client is identified by its [identifier].
///
/// The client credentials must have at least one of: shared secret,
/// RSA public key or RSA private key. If it has more than one of
/// them, it could be used with more than one signature method. The shared
/// secret is needed for the HMAC-SHA1 and PLAINTEXT signature methods. The
/// RSA private key and RSA public key are both needed to create signatures for
/// RSA-SHA1. But for validating RSA-SHA1 signatures, only the RSA public key
/// is needed.
///
/// Note: we do not know why signing requires the public key, but that's what
/// the PointyCastle package requires.

class ClientCredentials {
  /// Constructor for a set of client credentials.
  ///
  /// For backward compatibility, the [sharedSecret] parameter is always required.
  /// If there is no token secret (i.e. the client credentials only needs to
  /// work with RSA-SHA1), pass in null for the token secret.

  ClientCredentials(this.identifier, this.sharedSecret,
      {this.publicKey, this.privateKey}) {
    if (identifier == null) {
      throw ArgumentError.notNull('token');
    }

    if (sharedSecret == null && publicKey == null && privateKey == null) {
      // At least one of these must be provided (since even PLAINTEXT requires
      // a shared secret).
      throw ArgumentError('no shared secret, public or private key');
    }
  }

  /// Original name for the client identifier.
  ///
  /// Deprecated because the word "token" can be confused with the OAuth term
  /// for the "access token". Token is not used in OAuth in relationship to the
  /// client. OAuth terminology is confusing enough already!
  /// Use [identifier] instead.
  @deprecated
  String get token => identifier;

  /// Original name for the shared secret.
  ///
  /// Deprecated because the word "token" is confusing in this context.
  /// Use [sharedSecret] instead.
  @deprecated
  String get tokenSecret => sharedSecret;

  /// Identifier for the client.
  ///
  /// Previous versions of the OAuth specification referred to this as the
  /// "consumer key".

  final String identifier;

  /// Shared secret for authenticating the client.
  ///
  /// Previous version of the OAuth specification referred to this as the
  /// "consumer secret".

  final String sharedSecret;

  final RSAPublicKey publicKey;
  final RSAPrivateKey privateKey;
}
