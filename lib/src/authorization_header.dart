library authorization_header;

import 'dart:math';

import 'signature_method.dart';
import 'client_credentials.dart';
import 'credentials.dart';
import 'exceptions.dart';

//################################################################
/// A class describing Authorization Header.
///
/// An OAuth1 authorization header consists of a set of parameters: name-value
/// pairs. Names are case-sensitive and at most one name-value pair can exist
/// any given name.
///
/// http://tools.ietf.org/html/rfc5849#section-3.5.1

class AuthorizationHeader {
  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Internal default constructor.
  ///
  /// Creates an [AuthorizationHeader] that has no parameters.
  ///
  /// This is used by OAuth1 clients to create an Authorization header to put
  /// into HTTP requests to the OAuth server.
  ///
  /// This is internal because it is only needed by the OAuth1 library, for
  /// implementing the higher level functions of a client. Application programs
  /// only need to use those higher level functions: they should not have need
  /// to directly create AuthorizationHeaders (other than for OAuth1 servers
  /// to parse the Authorization header received in HTTP requests).
  ///
  /// TODO: rename this to _internal if the different libraries are unified
  /// into a single oauth1 library. Currently, calling it _internal will not
  /// work because it is invoked in the "authorization" and "oauth1_client"
  /// libraries.

  AuthorizationHeader.empty();

  //================================================================
  // Static members

  // Standard OAuth1 parameter names

  static const String oauth_nonce = 'oauth_nonce';
  static const String oauth_signature_method = 'oauth_signature_method';
  static const String oauth_timestamp = 'oauth_timestamp';
  static const String oauth_consumer_key = 'oauth_consumer_key';
  static const String oauth_version = 'oauth_version';
  static const String oauth_token = 'oauth_token';
  static const String oauth_signature = 'oauth_signature';
  static const String oauth_verifier = 'oauth_verifier';
  static const String oauth_callback = 'oauth_callback';

  /// Scheme used at the beginning of the Authorization header value
  ///
  /// Note: this value is case insensitive (see section 3.5.1 of RFC 5849).

  static const String scheme = 'OAuth';

  /// The version string "1.0"
  ///
  /// In OAuth1, the oauth_version parameter is optional. But if it is present,
  /// it must always have this value.
  ///
  /// This value will never change. Programs may want to use this constant,
  /// instead of having literal string values of "1.0" throughout the code
  /// (and risking a mistake).

  static const String version = '1.0';

  static const String _nonceChars =
      '23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';

  //================================================================
  // Static members

  /// Length of generated nonces.
  ///
  /// If a nonce is not provided to [sign], a random string of this length is
  /// generated for the nonce.

  int nonceLength = 8;

  /// Random number generator used to generate nonce values.

  final Random _nonceRnd = Random(DateTime.now().millisecondsSinceEpoch);

  //================================================================
  // Members

  /// All parameters except for any oauth_signature.
  ///
  /// The signature is stored separately in [_signature] so the _signature base
  /// string_ can be calculated from everything found in this map (without
  /// needing to remove the signature from it).

  final Map<String, String> _params = <String, String>{};

  /// The oauth_signature parameter.
  ///
  /// Unlike all the other parameters, the signature is stored in this
  /// separate member instead of in [_params].
  ///
  /// Value is null if there is no signature (usually after the header has been
  /// initialized but before it has been signed.)

  String _signature;

  //================================================================
  // Methods

  void addAll(Map<String, List<String>> properties) {
    properties.forEach((String key, List<String> values) {
      _params[key] = values.first; // TODO: handle multiple parameters
    });
  }

  //----------------------------------------------------------------
  /// Adds parameters from an OAuth authorization header.
  ///
  /// Parses the [str] as the value from an Authorization header. If it is not
  /// an OAuth authorization header (i.e. the value does not start with the
  /// "OAuth" scheme (case insensitive)) then false is returned and it is
  /// ignored.
  ///
  /// True is returned if the value is an OAuth authorization header and the
  /// parameters in it have been added.
  ///
  /// Throws [FormatException] if the string is not a valid authorization header
  /// value. For example, if it does not start with "OAuth" or is missing
  /// parameters such as "oauth_consumer_key", "oauth_nonce" and
  /// "oauth_version".
  ///
  /// This is used when implementing an OAuth1 server, and is used to parse the
  /// "Authorization" header received from the HTTP requests. After it has been
  /// parsed, its values can be examined to identify the client and temporary
  /// credentials or access token. After looking up the credentials for the
  /// client (and optionally the shared secret of the temporary credential or
  /// access token), the signature in the header can be validated by
  /// invoking the [validate] method. If the signature is valid, the header
  /// can then be used.
  ///
  /// Note: besides the Authorization header, an OAuth1 server may be passed
  /// parameters from the body of the request and/or query parameters.
  /// See sections 3.5.2 and 3.5.3 of RFC 5849. This library does not
  /// include an implementation of that, since it would require importing
  /// "dart:io" which would prevent this library from being used in the browser.

  bool addFromAuthorizationHeader(String str) {
    // The string must start with the scheme ("OAuth" case insensitive).

    final String matchLowercase = '$scheme '.toLowerCase(); // with the space
    if (str.length < matchLowercase.length) {
      return false;
    }
    final String start = str.substring(0, matchLowercase.length);
    if (start.toLowerCase() != matchLowercase) {
      return false;
    }

    // Extract all the parameters from the rest of the string

    for (final String c in str.substring(scheme.length).split(',')) {
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
        case oauth_signature:
          if (_signature != null) {
            throw const FormatException('duplicate $oauth_signature');
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
    // Check parameters are correct according to section 3.1 of RFC5849
    // <https://tools.ietf.org/html/rfc5849#section-3.1>

    // Check consumer key is present

    if (!_params.containsKey(oauth_consumer_key)) {
      throw const FormatException('$oauth_consumer_key missing');
    }

    // oauth_token optional if request is not associated with a resource owner

    if (_params[oauth_signature_method] == null) {
      throw const FormatException('$oauth_signature_method missing');
    }

    if (signatureMethod != SignatureMethods.plaintext.name) {
      // Timestamp and nonce are optional for the "PLAINTEXT" signature method,
      // so is mandatory for everything else (i.e. for HMAC-SHA1 and RSA-SHA1)

      final String timestamp = _params[oauth_timestamp];
      if (timestamp == null) {
        throw const FormatException('$oauth_timestamp missing');
      }
      if (!RegExp(r'^\d+$').hasMatch(timestamp)) {
        throw const FormatException('$oauth_timestamp invalid'); // not integer
      }

      final String nonce = _params[oauth_nonce];
      if (nonce == null) {
        throw const FormatException('$oauth_nonce missing');
      }
      if (nonce.isEmpty) {
        throw const FormatException('$oauth_nonce is empty');
      }
    }

    // Check optional version. If present, it must be "1.0"

    final String v = _params[oauth_version];
    if (v != null && v != version) {
      throw FormatException('$oauth_version unsupported: $v');
    }

    return true;
  }

  //----------------------------------------------------------------
  /// Signs the authorization header.
  ///
  /// Calculates an oauth_signature property and adds it to the header.
  /// It also adds (or overwrites any existing values for) these properties:
  /// oauth_time_stamp, oauth_signature_method, oauth_nonce,
  /// oauth_consumer_key. And if [tokenCredentials] are provided, it also
  /// adds the oauth_token parameter.
  ///
  /// If provided, it uses the [timestamp] for the timestamp. Otherwise, the
  /// number of seconds since 1970-01-01 00:00Z is used.
  ///
  /// If provided, the [nonce] is used for the nonce. Otherwise, a random value
  /// is generated for it.
  ///
  /// For debugging, sometimes it is useful to see the _signature base string_
  /// that is being signed. If provided, the [debugBaseString] is invoked with
  /// its value.

  void sign(String method, String url, ClientCredentials client,
      SignatureMethod signatureMethod,
      {Credentials tokenCredentials,
      int timestamp,
      String nonce,
      void debugBaseString(String str)}) {
    if (_params.containsKey(oauth_verifier) &&
        _params[oauth_version] != version) {
      // While oauth_version is optional, if present its value must be "1.0".
      // (from Section 3.1 or RFC5849)
      throw StateError('$oauth_version is not $version');
    }

    if (timestamp == null) {
      timestamp = (DateTime.now().millisecondsSinceEpoch / 1000).floor();
    } else {
      if (timestamp < 0) {
        throw ArgumentError.value(
            timestamp, 'timestamp', 'must be a positive integer');
      }
    }

    if (nonce == null) {
      // Generate a nonce
      nonce = _generateNonce();
    } else {
      // Check provided nonce is suitable
      if (nonce.isEmpty) {
        throw ArgumentError.value(nonce, 'nonce', 'empty string not sensible');
      }
    }

    // Set parameters that are needed for a properly signed header

    _params[oauth_consumer_key] = client.identifier;
    _params[oauth_signature_method] = signatureMethod.name;
    _params[oauth_nonce] = nonce;
    _params[oauth_timestamp] = timestamp.toString();

    if (tokenCredentials != null) {
      _params[oauth_token] = tokenCredentials.token;
    }

    _params.remove(oauth_signature); // must not have signature in parameters

    // Create the signature and set it

    _signature = _createSignature(method, url, _params, signatureMethod, client,
        tokenCredentials: tokenCredentials, debugBaseString: debugBaseString);
  }

  //---------------
  /// Method to generate a random string for use as a nonce.

  String _generateNonce() {
    final StringBuffer buf = StringBuffer();
    for (int x = 0; x < nonceLength; x++) {
      buf.write(_nonceChars[_nonceRnd.nextInt(_nonceChars.length)]);
    }
    return buf.toString();
  }

  //----------------------------------------------------------------
  /// The value for use in the HTTP Authorization header.
  ///
  /// Throws a [StateError] if the header has not been signed.

  String headerValue() {
    if (_signature != null) {
      // Start with "OAuth "
      final StringBuffer buf = StringBuffer('$scheme ');

      // Add all the parameters except the signature

      buf.write(_params.keys.map((String k) {
        return '$k="${Uri.encodeComponent(_params[k])}"';
      }).join(', '));

      // Add the signature

      assert(_params.isNotEmpty);
      buf.write(', $oauth_signature="${Uri.encodeComponent(_signature)}"');

      return buf.toString();
    } else {
      throw StateError('AuthorizationHeader has not been signed');
    }
  }

  //----------------------------------------------------------------

  @override
  String toString() {
    final List<String> components = <String>[];

    _params.forEach((String k, String v) => components.add('"$k":"$v"'));
    if (_signature != null) {
      components.add('"$oauth_signature":"$_signature"');
    }

    return '{${components.join(', ')}}';

    // Note: this string format is deliberately NOT the same as that used in the
    // Authorization header value, so programs cannot accidentally use this for
    // the wrong purpose. This toString method can be used to display a
    // partial or unsigned header, or an invalid header that had been parsed
    // from bad input; whereas the [headerValue] method should only be used for
    // complete and correct headers.
  }

  //----------------------------------------------------------------
  /// Validates the header's signature.
  ///
  /// Implements section 3.2 of RFC5849
  /// <https://tools.ietf.org/html/rfc5849#section-3.2>, except for the scope
  /// and status of the token, if present.
  ///
  /// Will throw a [ValidationException] if the signature is not valid.
  /// Otherwise, no exception is thrown.

  void validate(String method, String url, ClientCredentials clientCredentials,
      String tokenSecret1,
      {void debugBaseString(String str)}) {
    /// Determine the signature method

    SignatureMethod sigMethod;

    final String name = _params[oauth_signature_method];
    if (name == SignatureMethods.hmacSha1.name) {
      sigMethod = SignatureMethods.hmacSha1;
    } else if (name == SignatureMethods.rsaSha1.name) {
      sigMethod = SignatureMethods.rsaSha1;
    } else if (name == SignatureMethods.plaintext.name) {
      sigMethod = SignatureMethods.plaintext;
    } else {
      throw ValidationException(); // missing or non-standard signature method
    }

    // Calculate the signature base string

    final String baseStr = _baseString(method, url, _params);

    if (debugBaseString != null) {
      debugBaseString(baseStr);
    }

    // Invoke the validate method for that signature method

    if (!sigMethod.validate(
        _signature, baseStr, clientCredentials, tokenSecret1)) {
      throw ValidationException(); // validation failed
    }

    // validation successful: method finishes without throwing an exception
  }

  //================================================================
  // Methods for retrieving common OAuth1 parameters

  /// Client identifier
  ///
  /// Value is null if the `oauth_consumer_key` parameter is not set.

  String get clientIdentifier => _params[oauth_consumer_key];

  /// Token identifier or temporary credential identifier
  ///
  /// Value is null if the `oauth_token` parameter is not set.

  String get token => _params[oauth_token];

  /// Verifier
  ///
  /// Value is null if the `oauth_verifier` parameter is not set.

  String get verifier => _params[oauth_verifier];

  /// Callback
  ///
  /// Value is null if the `oauth_callback` parameter is not set.

  String get callback => _params[oauth_callback];

  /// Signature method
  ///
  /// Value is null if the `oauth_signature_method` parameter is not set.

  String get signatureMethod => _params[oauth_signature_method];

  /// Retrieves the nonce.
  ///
  /// Value is null if the `oauth_nonce` parameter is not set.

  String get nonce => _params[oauth_nonce];

  /// Retrieves the timestamp.
  ///
  /// Note: OAuth defines the timestamp as a positive integer, but does not
  /// necessarily reflect time. Section 3.3 of RFC5849 says, the server
  /// documentation could define what it requires for the timestamp.
  ///
  /// Value is null if the `oauth_timestamp` parameter is not set.

  String get timestamp => _params[oauth_timestamp];

  /// Retrieve parameter value.
  ///
  /// Value is null if the parameter with name [key] is not set.

  String operator [](String key) => _params[key];

  /// Sets a parameter value.
  ///
  /// Sets the [key] named parameter to [value].

  void operator []=(String key, String value) {
    _params[key] = value;
  }

  //================================================================
  // Static methods

  //----------------------------------------------------------------
  /// Calculate the signature base string.
  ///
  /// The _signature base string_ is defined by section 3.4.1 of RFC5849.
  /// <https://tools.ietf.org/html/rfc5849#section-3.4.1>
  ///
  /// It is consistent, reproducible concatenation of several of the HTTP
  /// request elements into a single string, and is used as an input to the
  /// "HMAC-SHA1" and "RSA-SHA1" signature methods.
  ///
  ///

  static String _baseString(
      String method, String url, Map<String, String> params) {
    // Referred from https://dev.twitter.com/docs/auth/creating-signature
    if (params.isEmpty) {
      throw ArgumentError('params is empty.');
    }

    final Uri uri = Uri.parse(url);

    //
    // Collecting parameters
    //

    // 1. Percent encode every key and value that will be signed.

    final Map<String, String> encodedParams = <String, String>{};

    params.forEach((String k, String v) {
      encodedParams[Uri.encodeComponent(k)] = Uri.encodeComponent(v);
    });
    uri.queryParameters.forEach((String k, String v) {
      encodedParams[Uri.encodeComponent(k)] = Uri.encodeComponent(v);
    });

    // TODO: handle multiple values for the same parameter name correctly

    params.remove('realm'); // TODO: fix: remove from encodedParams?

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

  //----------------------------------------------------------------

  /// Create signature in ways referred from
  /// https://dev.twitter.com/docs/auth/creating-signature.

  static String _createSignature(
      String method,
      String url,
      Map<String, String> params,
      SignatureMethod signatureMethod,
      ClientCredentials clientCreds,
      {Credentials tokenCredentials,
      void debugBaseString(String str)}) {
    // Calculate the signature base string

    assert(!params.containsKey(oauth_signature));

    final String baseStr = _baseString(method, url, params);

    if (debugBaseString != null) {
      // For debugging, invoke the function provided by the caller so it can
      // see what the _signature base string_ was being signed.
      debugBaseString(baseStr);
    }

    return signatureMethod.sign(
        baseStr, clientCreds, tokenCredentials?.tokenSecret);
  }
}
