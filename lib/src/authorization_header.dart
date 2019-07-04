library authorization_header;

import 'signature_method.dart';
import 'client_credentials.dart';
import 'credentials.dart';
import 'exceptions.dart';

/// A class describing Authorization Header.
/// http://tools.ietf.org/html/rfc5849#section-3.5.1

class AuthorizationHeader {
  final SignatureMethod _signatureMethod;
  final ClientCredentials _clientCredentials;
  final Credentials _credentials;
  final String _method;
  final String _url;
  final Map<String, String> _additionalParameters;

  // static final _uuid = new Uuid();

  AuthorizationHeader(this._signatureMethod, this._clientCredentials,
      this._credentials, this._method, this._url, this._additionalParameters);

  /// Set Authorization header to request.
  ///
  /// Below parameters are provided default values:
  /// - oauth_signature_method
  /// - oauth_signature
  /// - oauth_timestamp
  /// - oauth_nonce
  /// - oauth_version
  /// - oauth_consumer_key
  /// - oauth_token
  /// - oauth_token_secret
  ///
  /// You can add parameters by _authorizationHeader.
  /// (You can override too but I don't recommend.)
  @override
  String toString() {
    final Map<String, String> params = <String, String>{};

    params['oauth_nonce'] = DateTime.now().millisecondsSinceEpoch.toString();
    params['oauth_signature_method'] = _signatureMethod.name;
    params['oauth_timestamp'] =
        (DateTime.now().millisecondsSinceEpoch / 1000).floor().toString();
    params['oauth_consumer_key'] = _clientCredentials.token;
    params['oauth_version'] = '1.0';
    if (_credentials != null) {
      params['oauth_token'] = _credentials.token;
    }
    params.addAll(_additionalParameters);

    if (!params.containsKey('oauth_signature')) {
      params['oauth_signature'] = createSignature(_method, _url, params,
          _signatureMethod, _clientCredentials, _credentials);
    }

    final String authHeader = 'OAuth ' +
        params.keys.map((String k) {
          return '$k="${Uri.encodeComponent(params[k])}"';
        }).join(', ');
    return authHeader;
  }

  //----------------------------------------------------------------

  /// Create signature in ways referred from
  /// https://dev.twitter.com/docs/auth/creating-signature.

  static String createSignature(
      String method,
      String url,
      Map<String, String> params,
      SignatureMethod signatureMethod,
      ClientCredentials clientCredentials,
      [Credentials tokenCredentials]) {
    //Calculate the base string

    final String baseStr = baseString(method, url, params);

    // Getting a signing key

    // The signing key is simply the percent encoded consumer
    // secret, followed by an ampersand character '&',
    // followed by the percent encoded token secret:
    final String consumerSecret =
        Uri.encodeComponent(clientCredentials.tokenSecret);
    final String tokenSecret = tokenCredentials != null
        ? Uri.encodeComponent(tokenCredentials.tokenSecret)
        : '';
    final String signingKey = '$consumerSecret&$tokenSecret';

    //
    // Calculating the signature
    //

    final String signature = signatureMethod.sign(signingKey, baseStr);

    /*
    print('''
Client gen base string: $baseStr
  SHA-1 of base string: ${sha1.convert(utf8.encode(baseStr))}
  Signing with: $signingKey
  Signature: $signature
''');
    */

    return signature;
  }
  //----------------------------------------------------------------
  /// Calculate the base string.

  static String baseString(
      String method, String url, Map<String, String> params) {
    // Referred from https://dev.twitter.com/docs/auth/creating-signature
    if (params.isEmpty) {
      throw ArgumentError('params is empty.');
    }
    final Uri uri = Uri.parse(url);

    //
    // Collecting parameters
    //

    // 1. Percent encode every key and value
    //    that will be signed.
    final Map<String, String> encodedParams = <String, String>{};
    params.forEach((String k, String v) {
      encodedParams[Uri.encodeComponent(k)] = Uri.encodeComponent(v);
    });
    uri.queryParameters.forEach((String k, String v) {
      encodedParams[Uri.encodeComponent(k)] = Uri.encodeComponent(v);
    });
    params.remove('realm');

    // 2. Sort the list of parameters alphabetically[1]
    //    by encoded key[2].
    final List<String> sortedEncodedKeys = encodedParams.keys.toList()..sort();

    // 3. For each key/value pair:
    // 4. Append the encoded key to the output string.
    // 5. Append the '=' character to the output string.
    // 6. Append the encoded value to the output string.
    // 7. If there are more key/value pairs remaining,
    //    append a '&' character to the output string.
    final String baseParams = sortedEncodedKeys.map((String k) {
      return '$k=${encodedParams[k]}';
    }).join('&');

    //
    // Creating the signature base string
    //

    final StringBuffer base = StringBuffer();
    // 1. Convert the HTTP Method to uppercase and set the
    //    output string equal to this value.
    base.write(method.toUpperCase());

    // 2. Append the '&' character to the output string.
    base.write('&');

    // 3. Percent encode the URL origin and path, and append it to the
    //    output string.
    base.write(Uri.encodeComponent(uri.origin + uri.path));

    // 4. Append the '&' character to the output string.
    base.write('&');

    // 5. Percent encode the parameter string and append it
    //    to the output string.
    base.write(Uri.encodeComponent(baseParams.toString()));

    // Return the base string
    //
    return base.toString();
  }
}

//################################################################
/// Information from parsing an Authorization header.
///
/// TODO: modify Authorization Header so it can be used instead of a new class.

class AuthorizationHeaderParser {
  /// Constructor

  AuthorizationHeaderParser(String str) {
    if (!str.startsWith(_oauthPrefix)) {
      throw const FormatException('does not start with $_oauthPrefix');
    }

    for (final String c in str.substring(_oauthPrefix.length).split(',')) {
      // Process each of the key="value" components

      final String component = c.trim();

      // Split into key and the double quoted value

      final int equalsIndex = component.indexOf('=');
      if (equalsIndex < 0) {
        // Not found
        throw FormatException('component is not key=value: $component');
      } else if (equalsIndex == 0) {
        // No key (component is like "=something")
        throw FormatException('component missing key: $component');
      }
      final String key = component.substring(0, equalsIndex);
      final String quotedValue = component.substring(equalsIndex + 1);

      // Remove the double quotes around the value and decode it

      if (quotedValue.length < 2 ||
          quotedValue[0] != '"' ||
          quotedValue[quotedValue.length - 1] != '"') {
        throw FormatException('component value not double quoted: $component');
      }

      final String v = quotedValue.substring(1, quotedValue.length - 1);
      final String value = Uri.decodeComponent(v);

      // Save the key/value pair

      switch (key) {
        case 'oauth_signature':
          if (_signature != null) {
            throw const FormatException('duplicate oauth_signature');
          }
          _signature = value;
          break;
        default:
          if (_params.containsKey(key)) {
            throw FormatException('duplicate parameter: $key');
          }
          _params[key] = value;
          break;
      }
    }

    //--------
    // Check parameters according to section 3.1 of RFC5849
    // <https://tools.ietf.org/html/rfc5849#section-3.1>

    // Check consumer key is present

    if (!_params.containsKey('oauth_consumer_key')) {
      throw const FormatException('oauth_consumer_key missing');
    }

    // oauth_token optional if request is not associated with a resource owner

    // Check mandatory signature method

    final String sigMethodStr = _params['oauth_signature_method'];

    if (sigMethodStr == null) {
      throw const FormatException('oauth_signature_method missing');
    } else if (sigMethodStr != 'HMAC-SHA1') {
      throw FormatException(
          'oauth_signature_method unsupported: $sigMethodStr');
    }

    // Timestamp and nonce are optional for the "PLAINTEXT" signature method,
    // but that method is not supported by this implementation

    if (_params['oauth_timestamp'] == null) {
      throw const FormatException('oauth_timestamp missing');
    }
    if (_params['oauth_nonce'] == null) {
      throw const FormatException('oauth_nonce missing');
    }

    // Check optional version. If present, it must be "1.0"

    final String version = _params['oauth_version'];
    if (version != null && version != _supportedVersion) {
      throw FormatException('oauth_version unsupported: $version');
    }



  }

  //================================================================
  // Members

  /// All parameters except for any oauth_signature.
  ///
  /// The signature is stored separately in [_signature] so the _signature base
  /// string_ can be calculated from everything found in this map (without
  /// needing to remove the signature from it).
  ///
  /// The oauth_signature_method parameter is kept in this map, even though its
  /// value has been used to populate the [_signatureMethod].

  final Map<String, String> _params = <String,String>{};

  /// The oauth_signature parameter.
  ///
  /// Unlike all other parameters, this value is stored in this member instead
  /// of in [_params].

  String _signature;

  //================================================================
  // Constants

  static const String _oauthPrefix = 'OAuth ';

  static const String _supportedVersion = '1.0';

  //================================================================
  // Methods

  String get clientKey => _params['oauth_consumer_key'];

  String get verifier => _params['oauth_verifier'];

  String get token => _params['oauth_token'];

  String get callback => _params['oauth_callback'];

  String operator[](String key) => _params[key];

  //----------------------------------------------------------------

  @override
  String toString() {
    final List<String> components = <String>[];

    _params.forEach((String k, String v) => components.add('$k:$v'));
    if (_signature != null) {
      components.add('oauth_signature:$_signature');
    }

    return components.join(', ');
    // Note: this format is deliberately not the same as that used in the header
    // value, so the program cannot use this for the wrong purpose.
  }

  //----------------------------------------------------------------
  /// Implements section 3.2 of RFC5849
  /// <https://tools.ietf.org/html/rfc5849#section-3.2>, except for the scope
  /// and status of the token, if present.
  ///
  void validate(
      String method, String url, String consumerSharedSecret,
      String tokenSecret1) {

    /// Lookup the signature method


    SignatureMethod signatureMethod;
    final String sigMethodStr = _params['oauth_signature_method'];
    switch (sigMethodStr) {
      case 'HMAC-SHA1':
        signatureMethod = SignatureMethods.hmacSha1;
        break;
    }
    assert(signatureMethod != null, 'signature method check failed');

    // The signing key is simply the percent encoded consumer
    // secret, followed by an ampersand character '&',
    // followed by the percent encoded token secret:
    final String consumerSecret = Uri.encodeComponent(consumerSharedSecret);
    final String tokenSecret =
    tokenSecret1 != null ? Uri.encodeComponent(tokenSecret1) : '';
    final String signingKey = '$consumerSecret&$tokenSecret';

    final String baseStr = AuthorizationHeader.baseString(method, url, _params);
    final String calculatedSig = signatureMethod.sign(signingKey, baseStr);

    /*
    print('''
Calculated base string: $baseStr
  SHA-1 of base string: ${sha1.convert(utf8.encode(baseStr))}
  Signing with: $signingKey
  Provided signature:   $_signature
  Calculated signature: $calculatedSig
''');
    */

/*
TODO: If using the "HMAC-SHA1" or "RSA-SHA1" signature methods, ensuring
      that the combination of nonce/timestamp/token (if present)
      received from the client has not been used before in a previous
 */

    if (calculatedSig != _signature) {
      throw ValidationException(); // validation failed
    }

    //return authHeader;
    // Successful
  }
}
