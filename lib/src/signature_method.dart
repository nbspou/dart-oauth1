library signature_method;

import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/asymmetric/api.dart';

import 'package:oauth1/oauth1.dart';

//################################################################
/// A class abstracting Signature Method.
/// http://tools.ietf.org/html/rfc5849#section-3.4
///
/// OAuth1 clients and OAuth1 servers are expected to use the standard
/// [SignatureMethod] objects from [SignatureMethods]. In particular,
/// [SignatureMethods.hmacSha1], [SignatureMethods.rsaSha1] and
/// [[SignatureMethods.plaintext].

class SignatureMethod {
  //================================================================
  // Constructors

  /// A constructor of SignatureMethod.
  const SignatureMethod._internal(
      this._name, this._signWithCredentials, this._validate);

  //================================================================
  // Members

  final String _name;

  final String Function(String signatureBaseString, ClientCredentials client,
      [String tokenSecret]) _signWithCredentials;

  final bool Function(String signature, String signatureBaseString,
      ClientCredentials client, String tokenSecret) _validate;

  //================================================================
  // Methods

  /// Signature Method Name
  String get name => _name;

  //----------------------------------------------------------------
  /// Creates a signature.
  ///
  /// Returns the signature of the [signatureBaseString] when signed using the
  /// [clientCredentials]. The [tokenSecret] may be null.
  ///
  /// Throws an [ArgumentError] if the client credentials are not suitable
  /// for the signature method. That is, for HMAC-SHA1 and PLAINTEXT, the
  /// client credentials must have a shared secret; and for RSA-SHA1, the client
  /// credentials must have an RSA private key.

  String sign(String signatureBaseString, ClientCredentials clientCredentials,
          [String tokenSecret]) =>
      _signWithCredentials(signatureBaseString, clientCredentials, tokenSecret);

  //----------------------------------------------------------------
  /// Validates a signature.
  ///
  /// Returns true if the [signature] is valid, otherwise false.
  ///
  /// The signature is valid if it is a valid signature of the
  /// [signatureBaseString] when validated with the [clientCredentials].
  /// The [tokenSecret] may be null.
  ///
  /// Throws an [ArgumentError] if the client credentials are not suitable
  /// for the signature method. That is, for HMAC-SHA1 and PLAINTEXT, the
  /// client credentials must have a shared secret; and for RSA-SHA1, the client
  /// credentials must have an RSA public key.

  bool validate(String signature, String signatureBaseString,
          ClientCredentials clientCredentials, String tokenSecret) =>
      _validate(signature, signatureBaseString, clientCredentials, tokenSecret);
}

//################################################################
/// Standard signature methods.
///
/// This class defines the standard [SignatureMethod] from OAuth1:
/// - HMAC-SHA1 (implemented by [hmacSha1])
/// - RSA-SHA1 (implemented by [rsaSha1])
/// - PLAINTEXT (implemented by [plaintext]).

abstract class SignatureMethods {
  //================================================================
  // Standard signature methods

  //----------------------------------------------------------------
  /// Implements the HMAC-SHA1 signature method.

  static const SignatureMethod hmacSha1 =
      SignatureMethod._internal('HMAC-SHA1', _hmacSign, _hmacVerify);

  //----------------------------------------------------------------
  /// Implements the RSA-SHA1 signature method.

  static const SignatureMethod rsaSha1 =
      SignatureMethod._internal('RSA-SHA1', _rsaSign, _rsaVerify);

  //----------------------------------------------------------------
  /// Implements the PLAINTEXT signature method.

  static const SignatureMethod plaintext =
      SignatureMethod._internal('PLAINTEXT', _plainSign, _plainVerify);

  //================================================================
  // Methods used for the standard signature methods.
  //
  // These have been separated from the above, so the above section is more
  // easy to read.

  //----------------------------------------------------------------
  // Methods for HMAC-SHA1
  // http://tools.ietf.org/html/rfc5849#section-3.4.2

  static String _hmacSign(
      String signatureBaseString, ClientCredentials clientCredentials,
      [String tokenSecret]) {
    return _hmacSignature(signatureBaseString, clientCredentials, tokenSecret);
  }

//----------------

  static bool _hmacVerify(
    String signature,
    String signatureBaseString,
    ClientCredentials clientCredentials,
    String tokenSecret,
  ) {
    final String expected =
        _hmacSignature(signatureBaseString, clientCredentials, tokenSecret);

    return expected == signature;
  }

//----------------

  static String _hmacSignature(String signatureBaseString,
      ClientCredentials clientCredentials, String tokenSecret) {
    final Hmac hmac =
        Hmac(sha1, _concatKeys(clientCredentials, tokenSecret).codeUnits);
    return base64.encode(hmac.convert(signatureBaseString.codeUnits).bytes);
  }

  //----------------------------------------------------------------
  // Methods for RSA-SHA1

  static String _rsaSign(
      String signatureBaseString, ClientCredentials clientCredentials,
      [String tokenSecret]) {
    /// Signing involves encrypting with the private key
    if (clientCredentials.privateKey == null) {
      throw ArgumentError.value(clientCredentials, 'clientCredentials',
          'not suitable for RSA-SHA1: no RSA private key');
    }

    final Signer signer = Signer('SHA-1/RSA');

    signer.init(
        true, PrivateKeyParameter<RSAPrivateKey>(clientCredentials.privateKey));

    final Signature sig =
        signer.generateSignature(ascii.encode(signatureBaseString));
    if (sig is RSASignature) {
      return base64.encode(sig.bytes);
    } else {
      throw StateError('Signer did not produce a RSASignature');
    }
  }

  //----------------

  static bool _rsaVerify(String signature, String signatureBaseString,
      ClientCredentials clientCredentials, String tokenSecret) {
    // Validating an RSA-SHA1 signature involves
    if (clientCredentials.publicKey == null) {
      throw ArgumentError.value(clientCredentials, 'clientCredentials',
          'not suitable for RSA-SHA1: no RSA public key');
    }

    final Uint8List sig = base64.decode(signature);

    final Signer signer = Signer('SHA-1/RSA');
    signer.init(
        false, PublicKeyParameter<RSAPublicKey>(clientCredentials.publicKey));
    return signer.verifySignature(
        ascii.encode(signatureBaseString), RSASignature(sig));
  }

  //----------------------------------------------------------------
  // Methods for PLAINTEXT
  // http://tools.ietf.org/html/rfc5849#section-3.4.4

  static String _plainSign(
      String signatureBaseString, ClientCredentials clientCredentials,
      [String tokenSecret]) {
    return _concatKeys(clientCredentials, tokenSecret);
  }

  //----------------

  static bool _plainVerify(String signature, String signatureBaseString,
      ClientCredentials clientCredentials, String tokenSecret) {
    final String expected = _concatKeys(clientCredentials, tokenSecret);
    return expected == signature;
  }

  //----------------------------------------------------------------
  /// Common method used by both HMAC-SHA1 and PLAINTEXT signing methods.
  ///
  /// This method implements the "key" for HMAC-SHA1 as defined in section 3.4.2
  /// of RFC 5849, and the value for the oauth_signature for PLAINTEXT as
  /// defined in section 3.4.4.

  static String _concatKeys(
      ClientCredentials clientCredentials, String tokenSecret) {
    if (clientCredentials.sharedSecret == null) {
      throw ArgumentError.value(clientCredentials, 'clientCredentials',
          'not suitable for signature method: no shared secret');
    }

    final String consumerPart =
        Uri.encodeComponent(clientCredentials.sharedSecret);
    final String tokenPart =
        tokenSecret != null ? Uri.encodeComponent(tokenSecret) : '';

    return '$consumerPart&$tokenPart';
  }
}
