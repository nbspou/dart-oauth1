library authorization_request;

import 'dart:convert';
import 'dart:math';

import 'signature_method.dart';
import 'client_credentials.dart';
import 'credentials.dart';
import 'exceptions.dart';

//################################################################
/// Information in an OAuth request.
///
/// Represents all the information that is signed by an OAuth signature, plus
/// the signature. This information consists of:
///
/// - the HTTP request method ("POST", "GET", etc.);
/// - the requested URI; and
/// - parameters, both:
///     - OAuth protocol parameters and
///     - parameters that are not a part of the OAuth protocol.
///
/// These parameters can be transmitted in an HTTP request as:
///  - an HTTP "Authorization" header;
///  - query parameters; and/or
///  - parameters in an "application/x-www-form-urlencoded" body.
///
/// The OAuth protocol parameters (those starting with "oauth_*") have at most
/// one value, but other parameters may have multiple values for the same name.
/// The name and values of parameters are both case-sensitive.
///
/// An OAuth1 _client_ should create an empty [AuthorizationRequest()] and
/// populate it with any non-OAuth protocol parameters from the body of the
/// HTTP request (if there is one); and optionally the _oauth_version_ if it
/// wants to transmit it. Then use the [sign] method to generate all the
/// OAuth protocol parameters. Any query parameters in the URI passed to the
/// _sign_ method are added to the signed parameters. The OAuth protocol
/// parameters can then be included in the HTTP request. The most simplest way
/// to do this is to use the [headerValue] and put that value into a HTTP
/// "Authorization" header.
///
/// An OAuth1 _server_ should use [AuthorizationRequest.fromHttpRequest] to
/// gather all the signed information from the HTTP request. The information is
/// then used to identify the client and lookup the client credentials, and
/// (depending on the endpoint) also identify and lookup temporary credentials
/// or tokens.
/// With the credentials, the signature from the request can be checked using
/// the [validate] method. If the signature is not valid, the HTTP request
/// should be rejected and an error response produced, otherwise the HTTP
/// request can be processed to produce a suitable response.

class AuthorizationRequest {
  // Note: this class was previously called "AuthorizationHeader", but has been
  // renamed to be more accurate, since the OAuth protocol parameters do not
  // have to appear in an Authorization header. It has also been expanded to
  // also track the method and URI, since these are needed for signing and
  // validation.

  //================================================================
  // Constructors

  //----------------------------------------------------------------
  /// Default constructor.
  ///
  /// Creates an empty [AuthorizationRequest]. It has no parameters, and the
  /// method, URI and realms are not set.
  ///
  /// This is used by OAuth1 clients to create an Authorization header.
  ///
  /// Typical clients can use the high-level protocol methods, instead of
  /// using this constructor directly. Those high-level protocol methods will
  /// use this constructor, populate, signs and encodes the parameters.

  AuthorizationRequest();

  //----------------------------------------------------------------
  /// Constructor from information obtained from a HTTP request.
  ///
  /// This method is used by OAuth1 servers, to process an OAuth protocol HTTP
  /// request.
  ///
  /// Pass in the request's HTTP [method], the requested [uri], all the
  /// HTTP "Authorization" headers in [authorizationHeaders] and the contents
  /// of the body (if the request has a MIME type of
  /// application/x-www-form-urlencoded".
  ///
  /// There can be multiple Authorization headers. It is safe to pass them
  /// all to this constructor, since it only processes those whose scheme is
  /// for OAuth (any other headers are ignored).
  ///
  /// If there is no body, null or the empty string can be passed in for the
  /// _urlEncodedBody_.
  ///
  /// Throws [FormatException] if the headers cannot be parsed.
  /// Note: this constructor does not check any of the OAuth protocol parameters
  /// for correctness: that is done when/if the [validate] method is invoked on
  /// the object.
  ///
  /// Note: this method does not take a HttpRequest as a parameter, because
  /// that would require importing the "dart:io" library and that would prevent
  /// this library from being used in some situations. Implementations of an
  /// OAuth servers will need to extra the necessary value from the HttpRequest
  /// and pass them to this constructor. See _example_server.dart_ for how
  /// what needs to be done.

  AuthorizationRequest.fromHttpRequest(String method, Uri uri,
      Iterable<String> authorizationHeaders, String urlEncodedBody) {
    _setFromMethodAndUri(method, uri);

    // Incorporate any Authorization headers

    _realms = <String>[];

    if (authorizationHeaders != null) {
      for (final String value in authorizationHeaders) {
        final String r = _parseAuthorizationHeader(value); // populates _params
        if (r != null) {
          _realms.add(r); // tracks the realms, in case the server wants them
        }
      }
    }

    if (urlEncodedBody != null) {
      // TODO: properly detect and handle encoding (it is not necessarily UTF-8)
      addAll(_splitQueryStringAll(urlEncodedBody, encoding: utf8));
    }
  }

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

  /// Scheme for an OAuth Authorization header
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

  static const String supportedVersion = '1.0';

  /// Alphabet from which the nonce is generated from.

  static const String _nonceChars =
      '23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';

  /// Minimum nonce length.
  ///
  /// The nonce cannot be shorter than this length.

  static const int _minNonceLength = 4;

  static const int _defaultNonceLength = 8;

  //================================================================
  // Static members

  /// Length of generated strings for the nonce.
  ///
  /// If the [sign] method needs to generate a nonce, this is the length of the
  /// random string generated (if it is not rejected as being too small).

  static int nonceLength = _defaultNonceLength;

  /// Random number generator used to generate nonce values.

  static final Random _nonceRnd = Random(DateTime.now().millisecondsSinceEpoch);

  //================================================================
  // Members

  String _method;

  Uri _urlWithoutQuery; // all query parameters are in [_params]

  final Map<String, List<String>> _params = <String, List<String>>{};

  List<String> _realms;

  //================================================================
  // Methods to retrieve values

  //----------------------------------------------------------------

  /// Retrieves the HTTP method for the OAuth information.
  ///
  /// Returns null if the OAuth information has not been signed.

  String get method => _method;

  //----------------------------------------------------------------
  /// Retrieves the URI that was signed.
  ///
  /// Any query parameters that were a part of the original URI are not
  /// included. They can be found in with the rest of the parameters.
  ///
  /// Returns null if the OAuth information has not been signed.

  Uri get uri => _urlWithoutQuery;

  //----------------------------------------------------------------
  /// Retrieve all parameters.
  ///
  /// This includes both the OAuth protocol parameters (those whose name starts
  /// with "oauth_") and other parameters.

  Map<String, List<String>> get parameters => _params;

  //----------------------------------------------------------------
  /// Retrieves all the values of a named parameter.
  ///
  /// Retrieves all the values of the parameter named [name].
  ///
  /// Returns null if no values are set for the parameter.

  Iterable<String> get(String name) => _params[name];

  //----------------------------------------------------------------
  /// Retrieve all the OAuth protocol parameters for an Authorization header.
  ///
  /// Produces a value suitable for representing the OAuth protocol parameters
  /// in an HTTP "Authorization" header. An optional [realm] can be included.
  ///
  /// For example, it will produce a string that starts with:
  ///
  ///     OAuth realm="https://example.com", oauth_consumer_key="...", ...
  ///
  /// Only the OAuth protocol parameters (those starting with "oauth_") are
  /// included. All other parameters are not included. The should be included
  /// in the HTTP request by other means (i.e. as query parameters or in the
  /// body).
  ///
  /// Throws a [StateError] if the header has not been signed, since it probably
  /// does not make sense to use an OAuth Authorization header that is not
  /// signed. If it is needed, get the OAuth protocol parameters using
  /// [oauthParams] to build the value.

  String headerValue({String realm}) {
    if (signature != null) {
      final String optionalRealm =
          (realm != null) ? 'realm="${Uri.encodeComponent(realm)}", ' : '';

      final List<String> components = <String>[];
      oauthParams().forEach((String k, String v) =>
          components.add('$k="${Uri.encodeComponent(v)}"'));

      return '$scheme $optionalRealm${components.join(', ')}';
    } else {
      throw StateError('OAuth parameters have not been signed');
    }
  }

  //----------------------------------------------------------------
  /// Retrieve all the OAuth protocol parameters.
  ///
  /// This can be used if the client wants to transmit the parameters using
  /// an alternative mechanism (e.g. query parameters or in the body). Normally,
  /// clients can simply use the [headerValue] to obtain all the OAuth protocol
  /// parameters as a string value for insertion into the HTTP header as an
  /// "Authorization" header.
  ///
  /// Throws [MultiValueParameter] if there are multiple values for any of
  /// the OAuth protocol parameters, since there can be at most only one of
  /// them.

  Map<String, String> oauthParams() {
    final Map<String, String> result = <String, String>{};

    for (final String name in _params.keys) {
      if (name.startsWith('oauth_')) {
        final List<String> values = _params[name];
        if (values.length == 1) {
          result[name] = values.first; // use the first and only value
        } else {
          assert(values.isEmpty, '_param values should never be an empty list');
          throw MultiValueParameter(name);
        }
      }
    }

    return result;
  }

  //----------------------------------------------------------------
  /// Gets a single OAuth protocol parameter.
  ///
  /// Throws a [MultiValueParameter] if there are multiple values, since OAuth
  /// protocol parameters can have at most one value.
  ///
  /// This is used internally to implement the getters. Programs using this
  /// library should use the getters or [oauthParams].

  String _oauthValue(String name) {
    if (_params.containsKey(name)) {
      final List<String> values = _params[name];
      if (values.length == 1) {
        return values.first;
      } else if (values.isNotEmpty) {
        throw MultiValueParameter(name);
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  //----------------------------------------------------------------
  /// The realms from the Authorization headers.
  ///
  /// If the information was created by [AuthorizationRequest.fromHttpRequest],
  /// this will be non-null. Its value will be the realms extracted from each of
  /// the OAuth Authorization headers that were processed. If the OAuth
  /// Authorization header did not have a realm, the value will be an empty
  /// string.
  ///
  /// Note: there will be fewer members than the number of Authorization headers
  /// passed into the [AuthorizationRequest.fromHttpRequest] method, if some of
  /// those were not for the OAuth scheme.

  Iterable<String> get realms => _realms;

  //================================================================
  // Methods for retrieving OAuth1 protocol parameters

  /// oauth_consumer_key parameter.
  ///
  /// This value identifies the client. The term "consumer key" comes from an
  /// older version of the OAuth 1.0 specification.
  ///
  /// Value is null if the `oauth_consumer_key` parameter is not set.

  String get clientIdentifier => _oauthValue(oauth_consumer_key);

  /// oauth_token paraemter.
  ///
  /// Token identifier or temporary credential identifier.
  ///
  /// Value is null if the `oauth_token` parameter is not set.

  String get token => _oauthValue(oauth_token);

  /// oauth_verifier parameter.
  ///
  /// Value is null if the `oauth_verifier` parameter is not set.

  String get verifier => _oauthValue(oauth_verifier);

  /// oauth_callback parameter.
  ///
  /// Value is null if the `oauth_callback` parameter is not set.

  String get callback => _oauthValue(oauth_callback);

  /// oauth_signature_method parameter.
  ///
  /// Value is null if the `oauth_signature_method` parameter is not set.

  String get signatureMethod => _oauthValue(oauth_signature_method);

  /// oauth_nonce parameter.
  ///
  /// Value is null if the `oauth_nonce` parameter is not set.

  String get nonce => _oauthValue(oauth_nonce);

  /// oauth_timestamp parameter.
  ///
  /// Note: OAuth defines the timestamp as the string representation of a
  /// positive integer. The value is usually the number of seconds since an
  /// epoch, but it does not have to be that: section 3.3 of RFC 5849 says the
  /// server documentation could define what it requires for the timestamp.
  ///
  /// Value is null if the `oauth_timestamp` parameter is not set.

  String get timestamp => _oauthValue(oauth_timestamp);

  /// oauth_signature parameter.

  String get signature => _oauthValue(oauth_signature);

  /// oauth_version parameter.
  ///
  /// This parameter is optional (i.e. can be null), but if set its value
  /// must be "1.0" (the [supportedVersion] constant is that value).

  String get version => _oauthValue(oauth_version);

  //================================================================
  // Methods to set/modify the values

  //----------------------------------------------------------------
  /// Sets a parameter to a single value.
  ///
  /// Sets the parameter named [name] to have a single [value]. If the parameter
  /// had any value or values, they are all discarded and replaced with just
  /// the new value.

  void set(String name, String value) {
    _params[name] = <String>[value];
  }

  //----------------------------------------------------------------
  /// Adds a single value to a parameter.
  ///
  /// Add the [value] to the existing values of [name]. If there were no values
  /// for the parameter, the value becomes its first and only value. If there
  /// were values for the parameter, they are all kept and the new value is
  /// added to them (even if the same value already exists for that name).
  ///
  /// All parameters can have multiple values for the same name, except for
  /// those with names starting with "oauth_". A [MultiValueParameter] is thrown
  /// if trying to add a second value to OAuth protocol parameters.

  void add(String name, String value) {
    if (!_params.containsKey(name)) {
      _params[name] = <String>[];
    } else {
      if (name.startsWith('oauth_')) {
        throw MultiValueParameter(name);
      }
    }
    _params[name].add(value);
  }

  //----------------------------------------------------------------
  /// Adds a set of parameters.
  ///
  /// Adds all the parameters in [extra] to the existing parameters.
  /// If a parameter already has value(s), the new values are added to them.
  ///
  /// Throws [MultiValueParameter] if the extra parameters contains multiple
  /// values for an OAuth protocol parameter, or contains one where a value
  /// already exists for it.

  void addAll(Map<String, Iterable<String>> extra) {
    extra.forEach((String name, Iterable<String> values) {
      if (values.isNotEmpty) {
        bool hasExistingValues = true;
        if (!_params.containsKey(name)) {
          _params[name] = <String>[];
          hasExistingValues = false;
        }

        if ((hasExistingValues || 1 < values.length) &&
            name.startsWith('oauth_')) {
          throw MultiValueParameter(name);
        }

        _params[name].addAll(values);
      }
    });
  }

  //----------------------------------------------------------------
  /// Removes all values of a parameter.

  void remove(String name) {
    _params.remove(name);
  }

  //----------------------------------------------------------------
  // Internal method used by [AuthenticationRequest.fromHttpRequest] and [sign].
  //
  // Sets the [method] and the [uri] is used to set parameters from its
  // query strings with the rest of it going to the the [_urlWithoutQuery].

  void _setFromMethodAndUri(String method, Uri uri) {
    _method = method.toUpperCase();

    // Save the URI without the query parameters

    _urlWithoutQuery = Uri(
        scheme: uri.scheme,
        userInfo: uri.userInfo,
        host: uri.host,
        port: uri.port,
        pathSegments: uri.pathSegments,
        fragment: uri.hasFragment ? uri.fragment : null);

    // Incorporate any query parameters from the URI into the parameters

    addAll(uri.queryParametersAll);
  }

  //================================================================
  // Methods to create and validate signatures

  //----------------------------------------------------------------
  /// Signs the OAuth information.
  ///
  /// Sets the [method] and [uri] (adding any query parameters in the URL to
  /// the set of parameters) and calculates a signature over all the
  /// information. The signature is stored in the object as the
  /// _oauth_signature_ parameter.
  ///
  /// The signature is produced using the [signatureMethod], the client's
  /// [clientCredentials]. The client credentials must be suitable for signing
  /// with the signature method (i.e. it must have an RSA private key for
  /// signing with RSA-SHA1, and a shared secret for signing with HMAC-SHA1 or
  /// PLAINTEXT). Depending on which OAuth request is being made, the optional
  /// [tokenCredentials] might be mandatory.
  ///
  /// If provided, it uses the [timestamp] for the timestamp. Otherwise, the
  /// current number of seconds since 1970-01-01 00:00Z is used.
  ///
  /// If provided, the [nonce] is used for the nonce. Otherwise, a random string
  /// of length [nonceLength] is generated for it (unless that length is deemed
  /// too small to be secure, in which case a default length is used).
  ///
  /// This method will set (i.e. remove any/all previous values) for:
  ///
  /// - oauth_consumer_key;
  /// - oauth_signature_method;
  /// - oauth_timestamp;
  /// - oauth_nonce;
  /// - oauth_signature; and
  /// - depending on if _tokenCredentials_ is provided or not, the oauth_token
  ///   is either set or removed.
  ///
  /// All other parameters are unchanged. If the HTTP request will
  /// have other parameters (i.e. oauth_callback, oauth_verifier, oauth_version
  /// or any other non-OAuth parameters - from URL query parameters and/or
  /// a url-encoded body), they must be setup before invoking this signing
  /// method.
  ///
  /// Most programs should ignore the return value. For debugging the internal
  /// implementation of OAuth, the _signature base string_ that was signed
  /// is returned. That value is not transmitted in the OAuth protocol.

  String sign(String method, Uri uri, ClientCredentials clientCredentials,
      SignatureMethod signatureMethod,
      {Credentials tokenCredentials, int timestamp, String nonce}) {
    _setFromMethodAndUri(method, uri);

    if (version != null && version != supportedVersion) {
      // While oauth_version is optional, if present its value must be "1.0".
      // (from Section 3.1 or RFC 5849)
      throw BadParameterValue('unsupported', oauth_version, version);
    }

    int timestampToUse;
    if (timestamp == null) {
      // Use current time as a timestamp
      timestampToUse = (DateTime.now().millisecondsSinceEpoch / 1000).floor();
    } else {
      if (timestamp <= 0) {
        throw ArgumentError.value(timestamp, 'timestamp', 'must be a +ve int');
      }
      timestampToUse = timestamp; // use provided timestamp
    }

    String nonceToUse;
    if (nonce == null) {
      // Generate a nonce
      nonceToUse = _generateNonce();
    } else {
      if (nonce.isEmpty) {
        throw ArgumentError.value(nonce, 'nonce', 'empty string not sensible');
      }
      nonceToUse = nonce; // use provided nonce
    }

    // Set parameters that are needed for a properly signed header

    set(oauth_consumer_key, clientCredentials.identifier);
    set(oauth_signature_method, signatureMethod.name);
    set(oauth_timestamp, timestampToUse.toString());
    set(oauth_nonce, nonceToUse);

    if (tokenCredentials != null) {
      set(oauth_token, tokenCredentials.token);
    } else {
      remove(oauth_token);
    }

    // Create the signature and set it (i.e. replacing any existing signature)

    final String signatureBaseString = _baseString();

    final String theSignature = signatureMethod.sign(
        signatureBaseString, clientCredentials, tokenCredentials?.tokenSecret);

    set(oauth_signature, theSignature);

    return signatureBaseString; // for debugging (not needed by the protocol)
  }

  //----------------------------------------------------------------
  /// Validates the correct OAuth protocol parameters and the signature.
  ///
  /// The [clientCredentials] are used to validate the request, and must be
  /// for the client that signed the request (i.e. the client identity are the
  /// same) and be suitable for the signature method (i.e. has an RSA public key
  /// for RSA-SHA1, otherwise a has a shared secret).
  ///
  /// The optional [tokenSecret] is required or prohibited, depending on the
  /// particular OAuth request being validated. Note: this _validate_ method
  /// only requires the shared secret, but the _sign_ method uses both the token
  /// and the shared secret (which is why its argument is a _Credentials_
  /// instead of only the String shared secret).
  ///
  /// Implements section 3.2 of RFC 5849
  /// <https://tools.ietf.org/html/rfc5849#section-3.2>, except for the scope
  /// and status of the token, if present.
  ///
  /// Will throw a [BadOAuth] if the request is not valid.
  /// Otherwise, no exception is thrown if the validation succeeds.
  ///
  /// Most programs should ignore the return value. For debugging the internal
  /// implementation of OAuth, the _signature base string_ that was calculated
  /// from the parameters is returned. That value is not transmitted in the
  /// OAuth protocol.

  String validate(ClientCredentials clientCredentials, [String tokenSecret]) {
    if (_method == null || _urlWithoutQuery == null) {
      throw StateError('cannot validate: not signed or not from a HttpRequest');
    }

    //--------
    // Check parameters are correct according to section 3.1 of RFC 5849
    // <https://tools.ietf.org/html/rfc5849#section-3.1>
    //
    // Note: these checks use the getters, which will throw a [MultipleValues]
    // exception if there are multiple values for the same parameter name.

    if (clientIdentifier == null) {
      throw const MissingParameter(oauth_consumer_key);
    }
    if (clientIdentifier != clientCredentials.identifier) {
      throw BadParameterValue('does not match client credentials',
          oauth_consumer_key, clientIdentifier);
    }

    if (signatureMethod == null) {
      throw const MissingParameter(oauth_signature_method);
    }
    SignatureMethod sigMethod;
    final String smName = signatureMethod;
    if (smName == SignatureMethods.hmacSha1.name) {
      sigMethod = SignatureMethods.hmacSha1;
    } else if (smName == SignatureMethods.rsaSha1.name) {
      sigMethod = SignatureMethods.rsaSha1;
    } else if (smName == SignatureMethods.plaintext.name) {
      sigMethod = SignatureMethods.plaintext;
    } else {
      throw BadParameterValue('unsupported', oauth_signature_method, smName);
    }

    if (signatureMethod != SignatureMethods.plaintext.name) {
      // Timestamp and nonce are optional for the "PLAINTEXT" signature method,
      // so is mandatory for everything else (i.e. for HMAC-SHA1 and RSA-SHA1)

      if (timestamp == null) {
        throw const MissingParameter(oauth_timestamp);
      }
      if (!RegExp(r'^\d+$').hasMatch(timestamp)) {
        throw BadParameterValue('not +ve integer', oauth_timestamp, timestamp);
      }

      if (nonce == null) {
        throw const MissingParameter(oauth_nonce);
      }
      if (nonce.isEmpty) {
        throw BadParameterValue('empty nonce', oauth_nonce, nonce);
      }
    }

    // Check optional oauth_version. If present, it must be "1.0"

    final String v = version;
    if (v != null && v != supportedVersion) {
      throw BadParameterValue('unsupported version', oauth_version, version);
    }

    // Check the signature is present

    if (signature == null) {
      throw const MissingParameter(oauth_signature);
    }

    // Calculate the signature base string and check the signature against it

    final String calculatedSignatureBaseString = _baseString();

    if (!sigMethod.validate(signature, calculatedSignatureBaseString,
        clientCredentials, tokenSecret)) {
      throw SignatureInvalid(
          calculatedSignatureBaseString); // validation failed
    }

    // validation successful: method finishes without throwing an exception

    return calculatedSignatureBaseString; // for debugging, otherwise not needed
  }

  //----------------------------------------------------------------
  /// Calculate the signature base string.
  ///
  /// The _signature base string_ is defined by section 3.4.1 of RFC 5849.
  /// <https://tools.ietf.org/html/rfc5849#section-3.4.1>
  ///
  /// It is consistent, reproducible concatenation of several of the HTTP
  /// request elements into a single string, and is used as an input to the
  /// "HMAC-SHA1" and "RSA-SHA1" signature methods.

  String _baseString() {
    assert(_method != null);
    assert(_urlWithoutQuery != null);

    // Normalize parameters (as described in section 3.4.1.3.2 of RFC 5849)

    // 1. Percent encode every key and value that will be signed.
    //
    // Note: if the URI has query parameters, they will have already been
    // included into _params. Any parameters from a urlencoded body will also
    // have been already included into _params. Everything is in _params,
    // includeing any "oauth_signature" which this code will skip.

    final Map<String, List<String>> encodedParams = <String, List<String>>{};

    _params.forEach((String k, List<String> values) {
      if (k != oauth_signature) {
        final List<String> encValues = <String>[];

        for (String v in values) {
          encValues.add((v.isNotEmpty) ? _percentEncode(v) : '');
        }

        encodedParams[_percentEncode(k)] = encValues;
      }
    });

    // 2. Sort the encoded parameters by name (using ascending byte value)
    //    and multiple values by value.

    for (final List<String> values in encodedParams.values) {
      values.sort(); // sort multiple values by their encoded value
    }
    final List<String> sortedEncodedKeys = encodedParams.keys.toList()..sort();

    // 3. For each key/value pair:
    // 4. Append the encoded key to the output string.
    // 5. Append the '=' character to the output string.
    // 6. Append the encoded value to the output string.
    // 7. If there are more key/value pairs remaining,
    //    append a '&' character to the output string.

    final String normalizedParams = sortedEncodedKeys.map((String k) {
      final List<String> sortedValues = encodedParams[k];
      return sortedValues.map((String v) => '$k=$v').join('&');
    }).join('&');

    //
    // Creating the signature base string
    //

    final StringBuffer base = StringBuffer();
    // 1. Convert the HTTP Method to uppercase and set the
    //    output string equal to this value.
    base.write(_percentEncode(_method)); // note: already in uppercase

    // 2. Append the '&' character to the output string.
    base.write('&');

    // 3. Percent encode the _Base String URI_

    final String schemeLC = _urlWithoutQuery.scheme.toLowerCase();
    final String hostLC = _urlWithoutQuery.host.toLowerCase();
    final String portStr = (schemeLC == 'http' && _urlWithoutQuery.port == 80 ||
            schemeLC == 'https' && _urlWithoutQuery.port == 443)
        ? ''
        : ':${_urlWithoutQuery.port}';

    base.write(
        _percentEncode('$schemeLC://$hostLC$portStr${_urlWithoutQuery.path}'));

    // 4. Append the '&' character to the output string.
    base.write('&');

    // 5. Percent encode the parameter string and append it
    //    to the output string.
    base.write(_percentEncode(normalizedParams));

    // Return the base string
    //
    return base.toString();
  }

  //----------------
  // Percent encoding for signature base string from section 3.6 of RFC 5849.
  //
  // String is encoded as UTF-8: and safe characters are not encoded, but
  // all other characters are percent encoded (with uppercase hex characters).
  //
  // Note: this is NOT the same as the percent encoding implemented by RFC3986,
  // so the standard Uri.encode... methods cannot be used.

  static final Map<int, bool> _notEncodedCharcodes =
      Map<int, bool>.fromIterable(
          'abcdefghijklmnopqrstuvwxyz'
                  'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                  '0123456789'
                  '-._~'
              .codeUnits,
          key: (dynamic c) => c,
          value: (dynamic c) => true);

  static const List<String> _hexDigits = [
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    'A',
    'B',
    'C',
    'D',
    'E',
    'F'
  ];

  static String _percentEncode(String str) => utf8.encode(str).map((int c) {
        if (_notEncodedCharcodes.containsKey(c)) {
          return String.fromCharCode(c);
        } else {
          return '%${_hexDigits[(c >> 4) & 0x0F]}${_hexDigits[c & 0x0F]}';
        }
      }).join();

  //----------------------------------------------------------------
  /// Generate a random string for use as a nonce.

  String _generateNonce() {
    final StringBuffer buf = StringBuffer();
    final int len =
        (_minNonceLength < nonceLength) ? nonceLength : _defaultNonceLength;

    for (int x = 0; x < len; x++) {
      buf.write(_nonceChars[_nonceRnd.nextInt(_nonceChars.length)]);
    }
    return buf.toString();
  }

  //================================================================
  // Supporting method for parsing parameters

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
  ///
  /// Returns null if the header was not processed, because its scheme is not
  /// for OAuth. Otherwise, returns the "realm" value or the empty string if
  /// there wasn't a realm.

  String _parseAuthorizationHeader(String str) {
    // The string must start with the scheme ("OAuth" case insensitive).

    final String matchLowercase = '$scheme '.toLowerCase(); // with the space
    if (str.length < matchLowercase.length) {
      return null;
    }
    final String start = str.substring(0, matchLowercase.length);
    if (start.toLowerCase() != matchLowercase) {
      return null;
    }

    // Extract all the parameters from the rest of the string

    String realm = ''; // non-null value if there is no realm

    for (final String c in str.substring(scheme.length).split(',')) {
      // Process each of the key="value" components

      final String component = c.trim();

      // Split into key and the double quoted value

      final int equalsIndex = component.indexOf('=');
      if (equalsIndex < 0) {
        // Not found
        throw FormatException('component is not name=value: $component');
      } else if (equalsIndex == 0) {
        // No key (component is like "=something")
        throw FormatException('component missing name: $component');
      }
      final String name = component.substring(0, equalsIndex);
      final String quotedValue = component.substring(equalsIndex + 1);

      // Remove the double quotes around the value and decode it

      if (quotedValue.length < 2 ||
          quotedValue[0] != '"' ||
          quotedValue[quotedValue.length - 1] != '"') {
        throw FormatException('component value not double quoted: $component');
      }

      final String v = quotedValue.substring(1, quotedValue.length - 1);
      final String value = Uri.decodeComponent(v);

      if (name != 'realm') {
        add(name, value); // Save the key/value pair
      } else {
        realm = value;
      }
    }

    return realm;
  }

  //================================================================
  // Standard object methods

  //----------------------------------------------------------------

  @override
  String toString() {
    final StringBuffer buf = StringBuffer();

    if (_method != null || _urlWithoutQuery != null) {
      buf.write('$_method<$_urlWithoutQuery>');
    }

    buf.write('{');

    bool first = true;
    for (final String k in _params.keys) {
      for (final String v in _params[k]) {
        if (!first) {
          buf.write(', ');
        }
        first = false;
        buf.write('"$k":"$v"');
      }
    }

    buf.write('}');

    if (_realms != null) {
      buf.write('; realms=[${_realms.join(', ')}]');
    }

    return buf.toString();

    // Note: this string format is deliberately NOT the same as that used in the
    // Authorization header value, so programs shouldn't accidentally use this
    // for the wrong purpose. This method can be used to display incomplete
    // information that might not have been signed.
  }
}

//----------------------------------------------------------------
/// Parses an encoded query string
///
/// Unlike [Uri.splitQueryString], this method supports multiple values with
/// the same name.

Map<String, List<String>> _splitQueryStringAll(String query,
    {Encoding encoding}) {
  return query.split('&').fold(<String, List<String>>{},
      (Map<String, List<String>> map, String element) {
    String name;
    String value;

    final int index = element.indexOf('=');
    if (index == -1) {
      // No equal sign: treat as name= (i.e. value is the empty string)
      if (element.isNotEmpty) {
        name = Uri.decodeQueryComponent(element, encoding: encoding);
        value = '';
      }
    } else if (index != 0) {
      // Equal sign is present and is not the first character (name=value)
      name = Uri.decodeQueryComponent(element.substring(0, index),
          encoding: encoding);

      value = Uri.decodeQueryComponent(element.substring(index + 1),
          encoding: encoding);
    }

    if (name != null) {
      assert(value != null);
      if (!map.containsKey(name)) {
        map[name] = <String>[]; // create a new list for the first value
      }
      map[name].add(value); // append to list of values
    }

    return map;
  });
}
