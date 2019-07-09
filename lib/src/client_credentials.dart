library client_credentials;

import 'package:pointycastle/asymmetric/api.dart';

/// Client credentials.
///
/// A client credential has an [identifier] and at least one or more:
/// - shared secret,
/// - RSA public key, and/or
/// - RSA private key.
///
/// The shared secret is required for the
/// HMAC-SHA1 and PLAINTEXT signature methods. The RSA private key is required
/// to create RSA-SHA1 signatures. The RSA public key is required to validate
/// RSA-SHA1 signatures.

class ClientCredentials {
  /// Constructor for a set of client credentials.
  ///
  /// Creates a client credential for a client whose client identity is
  /// [identity].
  ///
  /// For backward compatibility, the [sharedSecret] parameter is a required
  /// parameter to this constructor. But if there is no shared secret (i.e. the
  /// client credentials only needs to work with RSA-SHA1), pass in null as the
  /// shared secret.

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

  /// Deprecated name for the client identifier.
  ///
  /// Deprecated because the word "token" can be confused with the OAuth term
  /// for the "access token". Token is not used in OAuth in relationship to the
  /// client. OAuth terminology is confusing enough already!
  /// Use [identifier] instead.
  @deprecated
  String get token => identifier;

  /// Deprecated name for the shared secret.
  ///
  /// Deprecated because the word "token" is confusing in this context.
  /// Use [sharedSecret] instead.
  @deprecated
  String get tokenSecret => sharedSecret;

  /// Identifier for the client.
  ///
  /// Previous versions of the OAuth specification referred to this as the
  /// "consumer key". Server documentation may call this something different,
  /// suc as "API key" or "username".

  final String identifier;

  /// Shared secret for authenticating the client.
  ///
  /// If this value is null, the clent credentials cannot be used to sign or
  /// validate requests using the HMAC-SHA1 or PLAINTEXT signature methods.
  ///
  /// Previous version of the OAuth specification referred to this as the
  /// "consumer secret". Server documentation may call this something different,
  /// such as "API secret" or "password".

  final String sharedSecret;

  /// RSA public key
  ///
  /// If this value is null, the client credentials cannot be used to validate
  /// requests created using the RSA-SHA1 signature method.

  final RSAPublicKey publicKey;

  /// RSA private key
  ///
  /// If this value is null, the client credentials cannot be used to sign
  /// requests using the RSA-SHA1 signature method.

  final RSAPrivateKey privateKey;
}
