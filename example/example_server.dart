/// Example OAuth1a server.
///
/// Implements a server for OAuth 1a three-legged-OAuth.
///
/// RFC 5849, "The OAuth 1.0 Protocol", April 2010.
///
/// Note: the RFC supercedes the older "OAuth Core 1.0 Revision A", 24 June
/// 2009, which is sometimes referred to as OAuth1a.
///
/// An OAuth server performs many tasks. In addition to implementing the
/// protocol, it also needs to track the _resource owners_ and registered
/// _clients_ and managing the lifecycle of _temporary credentials_ and _access
/// tokens_.
///
/// This program is organised into these sections:
///
///  - Constants
///  - Exception classes
///  - The entities:
///    - resource owners
///    - clients
///  - Code to generate random strings
///  - The OAuth1 tokens
///    - temporary credentials
///    - access tokens
///  - Framework for processing HTTP requests
///    - utility functions
///    - Http request handlers
///  - The main function

import 'dart:async';
import 'dart:convert';

import 'dart:io';
import 'dart:math';

import 'package:args/args.dart';
import 'package:encrypt/encrypt.dart';
import 'package:oauth1/oauth1.dart' as oauth1;

// Dart Linter overrides
// ignore_for_file: always_specify_types

//################################################################
// Constants
//
// These are all hard-coded to keep this example simple.

//----------------------------------------------------------------
// The host and port this server will listen on

final InternetAddress address = InternetAddress.loopbackIPv6;
const int port = 8080;

// Upper limit on the size of the HTTP request body.
const int _maxBodyLength = 1024 * 10;

//----------------------------------------------------------------
// Paths for the URIs implementing the OAuth1 protocol and protected resource

const String tmpCredentialRequestUrl = '/oauth/request_token';
const String resourceOwnerAuthUrl = '/oauth/authorize';
const String tokenRequestUrl = '/oauth/access_token';

const String restrictedResourceUrl = '/1.1/statuses/home_timeline.json';

const String authIssuerPostUrl = '/issue-auth';

//----------------------------------------------------------------
/// The resource owners
///
/// Entities that owns/controls the protected resources. These resource owners
/// can approve a client's request to access the protected resources.

final List<ResourceOwnerInfo> resourceOwners = [
  ResourceOwnerInfo('armstrong', 'password'),
  ResourceOwnerInfo('aldrin', '12345'),
  ResourceOwnerInfo('collins', 'monkey'),
];

//----------------------------------------------------------------
// The clients
//
// The programs that want to access the protected resources on this server.
// This test value corresponds to the default identity and secret hard-coded
// in the example client. Additional clients can be added via the command line.

final List<ClientInfo> registeredClients = [
  ClientInfo('dart-oauth1-test', 'LLDeVY0ySvjoOVmJ2XgBItvTV',
      sharedSecret: 'JmEpkWXXmY7BYoQor5AyR84BD2BiN47GIBUPXn3bopZqodJ0MV',
      pemPublicKey: '''
-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAsBYJRkO/c6eMgUosXpHXCBH5uE3+gR04IvkNzz5z9phaMxHUITSG
9qdJ7+sGgGnIl4Zd+NnwtfP+cUZaP46ySh+OHPFNt+MnwAd1hveJeG+9cB9Nd3je
ytdQHtqoE47kai7kNuLFEVHst0+wa3+aoJnrFckii5SK6g2tWiP9Z9IyiCLS7//U
GQQD3Q1zxqsTQCWKpQkcVKzkiq198pl2gI6qDsSO6cusg6tLqcf243C4/RkGf1EL
ug6AHte1T1ip0Czoj6VkmeiMUqSBvNmJOHLAuqaaltC+6Q07PC+Lm8/m1RJnQkmF
VOY1DDc/TSWwYO/DCsoarM3LjxFDTOSnhE4qZXn0f2hV48syqbavW0IKmCH+JHWW
oZgVm0ZDB3hMwlY2UaAnranw/EOONnAim2ebZoKbeaBX5KhtY1CNF6cMdNDx0D/B
4zZHcza3/BgN35PiVDj8teDX3bjwL2+sCkbaH9BKadal3VBw2RK7hPgMq26i57iY
AFDaXX9poFVZYrzHkVf2ja58TRF2fOZ85AV2uVoY0E3AN6GIPJQu16/SD6MPhneY
NiuqbV+RBsficySkdwRdcS8O+/FP928G67lEK2/akdhp0yhLlDQNlr2froIbBlaQ
xQVq0xyuiGr068ndvtFTiVVQh/JwC8bXMmh8IgI5A5XZb5AX0RpFcScCAwEAAQ==
-----END RSA PUBLIC KEY-----
      ''')
];

//################################################################
// Globals

/// Program options that can be set via the command line.

Arguments options;

/// Tracks nonce/timestamp/token combinations that have been seen to prevent
/// replay attacks.
///
/// TODO: implement a mechanism to delete old entries.
/// Currently, this just grows and grows until the server runs out of memory!

Map<String, bool> seenNonceCombination = {};

//################################################################
// Exceptions

class HandlerNotFound implements Exception {
  HandlerNotFound({this.methodKnown});
  final bool methodKnown;
}

class BadAuthException implements Exception {
  BadAuthException(this.message);
  final String message;
}

class BadRequestException implements Exception {
  BadRequestException(this.message);
  final String message;

  @override
  String toString() => message;
}

class ResourceOwnerUnknown implements Exception {
  ResourceOwnerUnknown(this.username);
  final String username;

  @override
  String toString() => 'Unknown resource owner: $username';
}

class ClientUnknown implements Exception {
  ClientUnknown(this.key);
  final String key;

  @override
  String toString() => 'Client unknown: $key';
}

class TemporaryCredentialUnknown implements Exception {
  TemporaryCredentialUnknown(this.id);
  final String id;

  @override
  String toString() => 'Temporary credential unknown: $id';
}

class TemporaryCredentialExpired implements Exception {
  TemporaryCredentialExpired(this.id);
  final String id;

  @override
  String toString() => 'Temporary credential expired: $id';
}

class AccessTokenUnknown implements Exception {
  AccessTokenUnknown(this.id);
  final String id;

  @override
  String toString() => id != null
      ? 'Access token unknown: $id'
      : 'Access token was not provided';
}

class AccessTokenExpired implements Exception {
  AccessTokenExpired(this.id);
  final String id;

  @override
  String toString() => 'Access token expired: $id';
}

class WrongLogin implements Exception {}

//################################################################
/// Resource owners.
///
/// Represents the username and password used to authenticate the resource owner
/// when they login to the Web page to approve access.

class ResourceOwnerInfo {
  ResourceOwnerInfo(this.username, this.password);

  String username;
  String password; // for example only: never store passwords in plaintext!

  /// Tests if an entered password matches the password.

  bool passwordMatches(String candidate) => candidate == password;

  /// Search for a resource owner by their [username].
  ///
  /// Throws [ResourceOwnerUnknown] if not found.

  static ResourceOwnerInfo lookup(String username) =>
      resourceOwners.firstWhere((x) => x.username == username,
          orElse: () => throw ResourceOwnerUnknown(username));
}

//################################################################
/// Information about clients this server recognises.
///
/// Clients are identified by its [identifier] and the [name] is used for
/// display purposes only.
///
/// If using HMAC-SHA1 or PLAINTEXT, the client and this server both need to
/// have the same [sharedSecret]. If using RSA-SHA1, the [pemPublicKey] needs to
/// be the PEM formatted public key that corresponds to the private key the
/// client has.

class ClientInfo {
  ClientInfo(this.name, String identifier,
      {String sharedSecret, String pemPublicKey}) {
    final keyParser = RSAKeyParser();
    final pubKey = pemPublicKey != null ? keyParser.parse(pemPublicKey) : null;

    credentials =
        oauth1.ClientCredentials(identifier, sharedSecret, publicKey: pubKey);
  }

  String name;

  oauth1.ClientCredentials credentials;

  /// Search for a client by their [key].
  ///
  /// Throws [ClientUnknown] if not found.

  static ClientInfo lookup(String key) =>
      registeredClients.firstWhere((x) => x.credentials.identifier == key,
          orElse: () => throw ClientUnknown(key));
}

//################################################################
// Code used to generate tokens, secrets and PINs.

/// Alphabet used by the [randomString].
///
/// In this example, the random string function is also used for the PIN, which
/// is expected to be entered by a person. So ambiguous letters are excluded
/// (e.g. i, l, 0, O).

const String _rndChars =
    '23456789abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ';

/// Random number generator used by [randomString].
///
/// This should be cryptographically secure, since it is used to generated the
/// shared secrets.

final _rnd = Random.secure();
// Less secure implementation:
//   final _rnd = Random(DateTime.now().millisecondsSinceEpoch);

/// Generates a random string.
///
/// A random string of [length] characters is returned.
///
/// This function is used for generating the tokens and secrets.

String randomString(int length) {
  final buf = StringBuffer();
  for (var x = 0; x < length; x++) {
    buf.write(_rndChars[_rnd.nextInt(_rndChars.length)]);
  }
  return buf.toString();
}

//################################################################
// Temporary credential

/// States of a temporary credential.
///
/// A temporary credential is created in the _pendingVerification_ state.
/// Then, when the resource owner approves access, it is changed to the
/// _verified_ state. Then, when the client exchanges it for an access token,
/// it is changed to the _used_ state. If it reaches its lifetime before
/// it enters the _used_ state, it becomes _expired_.
///
/// Previous versions of the specification referred to these as the "request
/// token" and its secret. This program only uses the word "token" in reference
/// to the "token credentials" (a.k.a. the access token).

enum TmpCredState { pendingVerification, verified, used, expired }

/// Temporary credentials.
///
/// See section 2 of RFC5849.

class TemporaryCredentialInfo {
  //================================================================
  /// Constructor
  ///
  /// Creates a new temporary credential for the [client] and records the
  /// [callback] they wanted to use.

  TemporaryCredentialInfo(this.client, this.callback)
      : identifier = randomString(16),
        secret = randomString(48),
        issued = DateTime.now() {
    _state = TmpCredState.pendingVerification;
    _allTmpCredentials[identifier] = this;
  }

  //================================================================
  // Static members

  /// Life time of a temporary token

  static const Duration _maxLifeTime = Duration(minutes: 2);

  /// Tracks every temporary credential created since the server started.
  ///
  /// This example implementation does not delete expired credentials, to keep
  /// the code simple and so it can tell the difference between an expired
  /// credential and an identifier that has never been issued.

  static final Map<String, TemporaryCredentialInfo> _allTmpCredentials = {};

  //================================================================
  // Members

  final String identifier;
  final String secret;

  /// When the temporary token was issued
  final DateTime issued;

  /// The client that requested the temporary credentials
  final ClientInfo client;

  /// The callback the client wanted to receive the verifier on (or "oob")
  final String callback;

  /// The resource owner who approved the temporary credential
  /// Only has a value if it has been approved.
  ResourceOwnerInfo approver;

  /// The verifier value assigned to this temporary credential
  ///
  /// Only has a value if it has been approved by a resource owner. The client
  /// must present this value to exchange this temporary credential for an
  /// access token.
  String _verifier;

  TmpCredState _state;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Makes the temporary token "verified".
  ///
  /// The state is changed from _pendingVerification_ to _verified_ and a
  /// value is assigned to the [verifier].
  ///
  /// This is used when the resource owner approves the access.

  void verified(ResourceOwnerInfo approvedBy) {
    assert(_state == TmpCredState.pendingVerification);
    _state = TmpCredState.verified;
    approver = approvedBy;
    _verifier = randomString(4);
  }

  //----------------------------------------------------------------
  /// Makes the temporary token "used".
  ///
  /// The state is changed from _verified_ to _used_.
  ///
  /// This is used when the client exchanges the temporary token for an access
  /// token.

  void used() {
    assert(_state == TmpCredState.verified);
    _state = TmpCredState.used;
  }

  //----------------------------------------------------------------
  /// The state of the temporary token.
  ///
  /// Initially, a temporary token is in the _pendingVerification_ state when it
  /// is created and issued to a client. When the resource owner approves
  /// access, the state becomes _verified_. Then when the client exchanges the
  /// temporary token for an access token, the state becomes _used_.
  ///
  /// If the temporary token has not been used before its time-to-live, its
  /// state becomes _expired_.

  TmpCredState get state => _state;

  //----------------------------------------------------------------
  /// The verifier value.
  ///
  /// This value which assigned by [verified] and which must match the value
  /// presented by the client when it exchanges this temporary token for an
  /// access token.

  String get verifier => _verifier;

  //----------------------------------------------------------------
  /// Lookups a temporary token by its identifier.
  ///
  /// Throws [TemporaryCredentialUnknown] if the is not known.

  static TemporaryCredentialInfo lookup(String identity) {
    final tmpCred = _allTmpCredentials[identity];
    if (tmpCred == null) {
      throw TemporaryCredentialUnknown(identity);
    }

    if (tmpCred._state != TmpCredState.used &&
        tmpCred._state != TmpCredState.expired &&
        DateTime.now().isAfter(tmpCred.issued.add(_maxLifeTime))) {
      // It has expired
      tmpCred._state = TmpCredState.expired;
      throw TemporaryCredentialExpired(identity);
    }

    return tmpCred;
  }
}

//################################################################
/// Manages the token credentials.
///
/// Previous versions of the specification referred to these as the "access
/// token" and its secret.

class TokenCredential {
  TokenCredential(this.client, this.resourceOwner)
      : identifier = randomString(32),
        secret = randomString(48),
        issued = DateTime.now() {
    _allTokens[identifier] = this;
  }

  //================================================================
  // Static members

  /// Life time of an access token.
  ///
  /// Depending on the server, some access tokens might never expire.
  /// In this example, they expire after a few minutes.

  static const Duration _maxLifeTime = Duration(minutes: 5);

  /// Tracks all the access tokens that have been created.
  ///
  /// This example implementation does not delete expired tokens, to keep
  /// the code simple and so it can tell the difference between an expired
  /// token and an identifier that has never been issued.

  static final Map<String, TokenCredential> _allTokens = {};

  //================================================================
  // Members

  final String identifier;
  final String secret;

  /// When the access token was issued
  final DateTime issued;

  // The client that the access token was issued to
  final ClientInfo client;

  // The resource owner that approved the access request
  final ResourceOwnerInfo resourceOwner;

  //================================================================
  // Methods

  //----------------------------------------------------------------

  /// Throws [AccessTokenUnknown] if the Access Token is not known.
  /// Throws [AccessTokenExpired] if the access token has expired.

  static TokenCredential lookup(String identity) {
    final token = _allTokens[identity];
    if (token == null) {
      throw AccessTokenUnknown(identity);
    }

    if (DateTime.now().isAfter(token.issued.add(_maxLifeTime))) {
      throw AccessTokenExpired(identity);
    }
    return token;
  }
}

//################################################################
// Framework for processing HTTP requests.
//
// Functions to handle HTTP requests match the [Handler] function type.
//
// Every URI supported by the server is represented in either [getHandlers]
// or [postHandlers], for handling HTTP GET requests and HTTP POST requests
// respectively. Those are maps from the path of the URI to the handler
// function.
//
// The [processHttpRequests] function listens for HTTP requests and dispatches
// them to the appropriate handler function.

//----------------------------------------------------------------
// Function type for HTTP request handling functions.

typedef Handler = Future<void> Function(HttpRequest request);

//----------------------------------------------------------------
// Maps of all supported HTTP requests.

final Map<String, Handler> getHandlers = {
  '/': handleHomePage,
  resourceOwnerAuthUrl: handleResourceOwnerAuthRequest,
  restrictedResourceUrl: handleExampleResource,
};

final Map<String, Handler> postHandlers = {
  tmpCredentialRequestUrl: handleTmpCredentialsRequest,
  tokenRequestUrl: handleTokenRequest,
  authIssuerPostUrl: handleResourceOwnerAuthRequestPost,
};

//----------------------------------------------------------------
/// Listen for HTTP requests and process them.

Future<void> processHttpRequests(HttpServer server) async {
  await for (final HttpRequest request in server) {
    final path = request.requestedUri.path;

    if (Verbosity.quiet.index < options.verbosity.index) {
      print('${DateTime.now()}: ${request.method} $path');
    }

    try {
      // Try to find a handler to process the request

      Handler handler;

      switch (request.method) {
        case 'GET':
          handler = getHandlers[path];
          break;
        case 'POST':
          handler = postHandlers[path];
          break;
        default:
          throw HandlerNotFound(methodKnown: false);
      }

      if (handler == null) {
        throw HandlerNotFound(methodKnown: true);
      }

      // Invoke the handler

      await handler(request);
    } catch (e) {
      // Something went wrong: generate an error HTTP response

      generateErrorResponse(e, request.response);
    }
  }
}

//----------------------------------------------------------------
/// Generates a HTTP response based on the exception that was thrown.
///
/// Warning: this might reveal more information to the user/client than a
/// production server should. This is just an example.

void generateErrorResponse(Object exception, HttpResponse resp) {
  if (exception is HandlerNotFound) {
    if (exception.methodKnown) {
      _errorHtml(HttpStatus.notFound, 'Not found', resp);
    } else {
      _errorHtml(HttpStatus.methodNotAllowed, 'Method not allowed', resp);
    }
  } else if (exception is BadAuthException) {
    _errorAuth(exception.message, resp);
  } else if (exception is oauth1.BadOAuth) {
    _errorAuth('Invalid request: $exception', resp);
  } else if (exception is BadRequestException) {
    _errorHtml(HttpStatus.badRequest, 'Bad request: $exception', resp);
  } else if (exception is WrongLogin) {
    _errorHtml(HttpStatus.badRequest, 'Invalid login', resp);
  } else {
    _errorHtml(HttpStatus.internalServerError, exception.toString(), resp);
  }
}

// Generates a HTML error page HTTP response.
// Only for use by [generateErrorResponse].

void _errorHtml(int status, String message, HttpResponse resp) {
  print('${DateTime.now()}:   $message');

  resp.statusCode = status;
  resp.headers.contentType = ContentType.html;

  resp.write('''<!DOCTYPE html>
<html>
<head>
<title>OAuth1 Example Server: Error</title>
<style type="text/css">
body {
  background: #eee;
  font-family: sans-serif;
}
</style>
</head>

<body>
<h1>Error</h1>

<p>$message</p>

<p><a href="/">Home</a></p>
</body>
</html>
''');

  resp.close();
}

// Generates an OAuth unauthorized HTTP response.
// Only for use by [generateErrorResponse].

void _errorAuth(String message, HttpResponse resp) {
  print('${DateTime.now()}: bad auth: $message');

  resp.statusCode = HttpStatus.unauthorized;
  resp.headers.contentType = ContentType('application', 'json');

  final realm = 'http://${hostname(address)}:$port';

  resp.headers.add('www-authenticate', 'OAuth realm="$realm');
  resp.write('{"errors":[{"message": "could not authenticate"}]\n');

  resp.close();
}

//################################################################
// Utility classes and functions

//----------------------------------------------------------------
/// Convert the address the server is listening on to a value that can be
/// used as the hostname in a URI.

String hostname(InternetAddress address) =>
    (address.isLoopback) ? 'localhost' : address.host;

//----------------------------------------------------------------
/// Query parameters
///
/// Represents parameters from the query parameters of a URI or from a
/// url-encoded body of a HTTP request. It is a set of name-value pairs, where
/// there could be multiple pairs with the same name and/or value. Both name
/// and value are case sensitive.

class QueryParams {
  /// Constructor that parses a query string.

  QueryParams.fromQueryString(String queryStr, {Encoding encoding = utf8}) {
    for (final String pair in queryStr.split('&')) {
      if (pair.isNotEmpty) {
        final index = pair.indexOf('=');
        if (index == -1) {
          // no "=": use whole string as key and the value is empty string
          final key = Uri.decodeQueryComponent(pair, encoding: encoding);
          _add(key, ''); // no "=" found, treat value as empty string
        } else if (index != 0) {
          final key = pair.substring(0, index);
          final value = pair.substring(index + 1);
          _add(Uri.decodeQueryComponent(key, encoding: encoding),
              Uri.decodeQueryComponent(value, encoding: encoding));
        } else {
          // Has "=", but is first character: key is empty string
          _add('',
              Uri.decodeQueryComponent(pair.substring(1), encoding: encoding));
        }
      }
    }
  }

  /// Limit on the size of POST request bodies

  static const int maxBodySize = 10 * 1024; // bytes

  final Map<String, List<String>> values = {};

  @override
  String toString() {
    final StringBuffer buf = StringBuffer();
    for (final key in values.keys) {
      buf.write('$key=[${values[key].map((s) => '"$s"').join(', ')}]');
    }
    return buf.toString();
  }

  void _add(String key, String value) {
    if (!values.containsKey(key)) {
      values[key] = []; // create array of values
    }
    values[key].add(value); // append new value to the array of values
  }

  /// Retrieve a single value.
  ///
  /// If there are multiple values with the same name, only the first is
  /// returned and the others are ignored.

  String operator [](String name) {
    if (values.containsKey(name)) {
      return values[name].first;
    } else {
      return null;
    }
  }

  /// Creates a [QueryParams] by parsing the body of a HTTP response where
  /// the MIME type is 'application/x-www-form-urlencoded'. This is usually
  /// produced by a POST request from a HTML form, but can also be used for
  /// other HTTP POST and PUT requests.

  static Future<QueryParams> fromBody(HttpRequest request) async {
    if (request.headers.contentType != null) {
      final String mimeType = request.headers.contentType.mimeType;
      if (mimeType != 'application/x-www-form-urlencoded') {
        throw BadRequestException('unexpected Content-Type: $mimeType');
      }

      final bodyBytes = <int>[];
      await for (final Iterable<int> bytes in request) {
        if (maxBodySize < bodyBytes.length + bytes.length) {
          throw BadRequestException('body too large');
        }
        bodyBytes.addAll(bytes);
      }

      final bodyStr = utf8.decode(bodyBytes, allowMalformed: false);

      return QueryParams.fromQueryString(bodyStr);
    } else {
      return null;
    }
  }
}

//----------------------------------------------------------------
/// Extracts parameters from an HTTP request.

Future<oauth1.AuthorizationRequest> _getOAuthRequest(
    HttpRequest request) async {
  // Get www-form-urlencoded body, if any

  String urlEncodedBody;

  final ContentType contentType = request.headers.contentType;
  if (contentType != null &&
      contentType.mimeType == 'application/x-www-form-urlencoded') {
    // Request has a Content-Type header and it is the expected mime-type

    final bodyBytes = <int>[];
    await for (final Iterable<int> bytes in request) {
      if (_maxBodyLength < bodyBytes.length + bytes.length) {
        throw BadRequestException('body too large');
      }
      bodyBytes.addAll(bytes);
    }

    if (contentType.charset != 'utf8') {
      throw FormatException('unsupported charset: ${contentType.charset}');
    }

    urlEncodedBody = utf8.decode(bodyBytes, allowMalformed: false);
  }

  // Extract all the parameters that are signed by OAuth1 from:
  // - query parameters in the URI
  // - OAuth authorization headers
  // - www-form-urlencoded body

  final params = oauth1.AuthorizationRequest.fromHttpRequest(request.method,
      request.requestedUri, request.headers['authorization'], urlEncodedBody);

  if (Verbosity.normal.index < options.verbosity.index) {
    print(params);
  }

  return params;
}

//----------------------------------------------------------------
/// Records and checks the nonce, timestamp and token.
///
/// Section 3.2 of RFC 5849 says: "If using the "HMAC-SHA1" or "RSA-SHA1"
/// signature methods, ensuring that the combination of nonce/timestamp/token
/// (if present) received from the client has not been used before in a previous
//  request (the server MAY reject requests with stale timestamps as
//  described in Section 3.3).

void checkNonce(oauth1.AuthorizationRequest auth) {
  if (auth.signatureMethod == oauth1.SignatureMethods.hmacSha1.name ||
      auth.signatureMethod == oauth1.SignatureMethods.rsaSha1.name) {
    final nonce = auth.nonce;
    assert(nonce != null, 'nonce missing: parser did not detect this');
    if (nonce == null || nonce.length < 4) {
      throw BadRequestException('Nonce is too short for my liking');
    }

    final timestamp = auth.timestamp;

    final token = auth.token;

    final combination = '$nonce:$timestamp:$token';
    if (seenNonceCombination.containsKey(combination)) {
      throw BadRequestException('OAuth HTTP request has already been received');
    }

    seenNonceCombination[combination] = true;
  }
}

//################################################################
// The HTTP request handlers

//----------------------------------------------------------------
/// Handle a request for a Temporary Credential.
///
/// This is the first leg in the three-legged-OAuth. The client sends a request
/// to this server to obtain a new temporary credential.

Future<void> handleTmpCredentialsRequest(HttpRequest request) async {
  assert(request.method == 'POST');

  // From the OAuth header, identify the client and validate the header was
  // signed by that client.

  final oauthRequest = await _getOAuthRequest(request);

  final client = ClientInfo.lookup(oauthRequest.clientIdentifier);
  if (Verbosity.quiet.index < options.verbosity.index) {
    print(
        '  request from client="${client.name}" using ${oauthRequest.signatureMethod}');
  }

  oauthRequest.validate(client.credentials); // no token secret for this request

  checkNonce(oauthRequest);

  // Get the callback the client has indicated it wants to use

  final callback = oauthRequest.callback;

  if (callback == null) {
    throw BadRequestException('oauth_callback missing');
  }
  if (callback != 'oob' && !callback.startsWith('http')) {
    throw BadRequestException(
        'oauth_callback is not "oob" or HTTP URL: $callback');
  }

  // Success: issue a temporary token to the client

  final tmpCred = TemporaryCredentialInfo(client, callback);

  if (Verbosity.quiet.index < options.verbosity.index) {
    print('  issued temporary credential: ${tmpCred.identifier}');
  }

  // Produce response containing the temporary credential

  final resp = request.response;

  resp.headers.contentType =
      ContentType('application', 'x-www-form-urlencoded');

  final Map<String, String> p = {
    'oauth_token': tmpCred.identifier,
    'oauth_token_secret': tmpCred.secret,
    'oauth_callback_confirmed': 'true',
  };

  resp.write(p.keys.map((k) => '$k=${Uri.encodeComponent(p[k])}').join('&'));
  resp.close();
}

//----------------------------------------------------------------
/// Resource Owner Authorization.
///
/// This is the second leg in the three-legged-OAuth. After obtaining a
/// temporary credential, the client will ask the resource owner to visit this
/// page (e.g. by redirecting their browser) to authorize the request for
/// access.
///
/// Implements section 2.2 of RFC5849
/// <https://tools.ietf.org/html/rfc5849#section-2.2>.

Future<void> handleResourceOwnerAuthRequest(HttpRequest request) async {
  assert(request.method == 'GET');

  // The temporary token is provided as a query parameter

  final tmpTokenId = request.uri.queryParameters['oauth_token'];
  final tmpCred = TemporaryCredentialInfo.lookup(tmpTokenId);

  if (tmpCred.state != TmpCredState.pendingVerification) {
    throw BadRequestException('temporary credential: ${tmpCred.state}');
  }

  // Produce response: a form asking the resource owner to login and approve

  final resp = request.response;
  resp.headers.contentType = ContentType.html;
  resp.statusCode = HttpStatus.ok;
  resp.write('''<!DOCTYPE html>
<html>
<head>
<title>OAuth1 Example Server: Authorizing client</title>
<style type="text/css">
body {
  background: #eee;
  font-family: sans-serif;
}
table.details th {
  text-align: right;
}
td {
  padding: 0ex 1em;
}
</style>
</head>

<body>
<h1>Authorizing client</h1>

<p>The <strong>${tmpCred.client.name}</strong> client has requested
permission to access your resources.</p>

<p>If you want to give it access, enter your username and password and press the
authorize button.</p>

<form method="POST" action="$authIssuerPostUrl">
<input name="oauth_token" type="hidden" value="$tmpTokenId">

<table>
  <tr>
    <th><label for="uid">Username:</label></th>
    <td><input id="uid" name="username"></td>
  </tr>
  <tr>
    <th><label for="pwd">Password:</label></th>
    <td><input id="pwd" name="password" type="password"></td>
  </tr>
  <tr>
    <td></td>
    <td><input type="submit" value="Authorize client app"></td>
  </tr>
</table>

</form>
</body>
</html>
  ''');

  resp.close();
}

//----------------
// Process the form

Future<void> handleResourceOwnerAuthRequestPost(HttpRequest request) async {
  try {
    assert(request.method == 'POST');

    final postParams = await QueryParams.fromBody(request);
    assert(postParams != null);

    // Check the username and password

    final owner = ResourceOwnerInfo.lookup(postParams['username']);

    if (!owner.passwordMatches(postParams['password'])) {
      throw WrongLogin();
    }

    // Mark the temporary credential as having been verified

    final tmpCred = TemporaryCredentialInfo.lookup(postParams['oauth_token']);

    if (tmpCred.state != TmpCredState.pendingVerification) {
      throw BadRequestException('temporary credential: ${tmpCred.state}');
    }

    // Success

    tmpCred.verified(owner);

    if (Verbosity.quiet.index < options.verbosity.index) {
      print('  approved by resource owner ${owner.username}'
          ' for temporary credential=${tmpCred.identifier}');
      print('  verifier for client to present: ${tmpCred.verifier}');
    }

    // Produce the response that returns the verifier to the client
    // (either directly via the callback the client provided when it asked for
    // the temporary credential) or display it for it to be done out-of-band.

    final resp = request.response;

    if (tmpCred.callback != 'oob') {
      // Redirect to the client's callback with information in query parameters

      final uri = Uri.parse(tmpCred.callback);
      uri.queryParameters['oauth_token'] = tmpCred.identifier;
      uri.queryParameters['oauth_verifier'] = tmpCred.verifier;

      resp.statusCode = HttpStatus.temporaryRedirect;
      resp.headers.set(HttpHeaders.locationHeader, uri.toString());
    } else {
      // Cannot use redirect. Display the value of the verification code.

      resp.headers.contentType = ContentType.html;
      resp.write('''<!DOCTYPE html>
<html>
<head>
<title>OAuth1 Example Server: Authorization successful</title>
<style type="text/css">
body {
  background: #eee;
  font-family: sans-serif;
}
code {
  display: block;
  padding: 1ex 1em;
  font-size: x-large;
}
</style>
</head>

<body>
<h1>Authorization successful</h1>

<p>Please provide the <em>${tmpCred.client.name}</em>
client this PIN: <code>${tmpCred.verifier}</code></p>
</body>
</html>
  ''');
    }

    resp.close();
  } on ResourceOwnerUnknown {
    // The username was wrong, but don't reveal that fact to the user.
    // Treat it the same as if the password was wrong.
    throw WrongLogin();
  }
}

//----------------------------------------------------------------
/// Issues token credentials.
///
/// This is the third leg in the three-legged-OAuth. The client has obtained
/// the verifier (either via a callback or via an out-of-band mechanism) and
/// now wants to exchange the temporary token for an access token.
///
/// Implements section 2.3 of RFC5849
/// <https://tools.ietf.org/html/rfc5849#section-2.3>.

Future<void> handleTokenRequest(HttpRequest request) async {
  assert(request.method == 'POST');

  // From the OAuth header, identify the client and the temporary credential,
  // validate the signature was produced by the client (for that temporary
  // credential) and that the verifier is correct for that temporary
  // credential.

  final oauthRequest = await _getOAuthRequest(request);
  if (Verbosity.quiet.index < options.verbosity.index) {
    print('  temporary credential=${oauthRequest.token}'
        ' verifier=${oauthRequest.verifier}'
        ' using ${oauthRequest.signatureMethod}');
  }

  final client = ClientInfo.lookup(oauthRequest.clientIdentifier);

  final tmpCred = TemporaryCredentialInfo.lookup(oauthRequest.token);

  oauthRequest.validate(client.credentials, tmpCred.secret);

  checkNonce(oauthRequest);

  if (tmpCred.verifier != oauthRequest.verifier) {
    // Incorrect verifier
    //
    // Normally this is ALWAYS an error. But for testing, the backdoor value
    // may be accepted as a substitute for the correct value.

    if (options.allowBackdoor && oauthRequest.verifier == 'backdoor') {
      // This is only for testing. Do not use in any production system!
      // It automatically authorizes the temporary credential (by the first
      // resource owner in the list) and treats the verifier as being correct.
      // To make testing quicker, this saves the tester from manually logging
      // into the server to authorize the request.
      print('  WARNING: treating verifier as correct even though it is not');
      tmpCred.verified(resourceOwners.first);
    } else {
      throw BadRequestException('wrong verifier');
    }
  }

  if (tmpCred.client.credentials.identifier != client.credentials.identifier) {
    throw BadRequestException('temporary credential does not belong to client');
  }
  if (tmpCred.state != TmpCredState.verified) {
    throw BadRequestException(
        'temporary credential has not been authorised by a resource owner');
  }

  // Success: issue the client an access token

  tmpCred.used(); // mark the temporary credential as used

  final TokenCredential accessToken = TokenCredential(client, tmpCred.approver);

  if (Verbosity.quiet.index < options.verbosity.index) {
    print('  issued access token: ${accessToken.identifier}');
  }

  // Produce response with the access token

  final resp = request.response;

  resp.headers.contentType =
      ContentType('application', 'x-www-form-urlencoded');

  final Map<String, String> p = {
    'oauth_token': accessToken.identifier,
    'oauth_token_secret': accessToken.secret,
    'screen_name': tmpCred.approver.username, // example of optional parameter
  };

  resp.write(p.keys.map((k) => '$k=${Uri.encodeComponent(p[k])}').join('&'));
  resp.close();
}

//----------------------------------------------------------------
/// Handler for the protected resource.
///
/// This is the access-restricted resource the client is ultimately trying to
/// access, but needs to go through the OAuth process to obtain an access token
/// to be able to access it.

Future<void> handleExampleResource(HttpRequest request) async {
  // From the OAuth header, get the client and access token and validate the
  // signature.

  final oauthRequest = await _getOAuthRequest(request);

  final client = ClientInfo.lookup(oauthRequest.clientIdentifier);

  String info;

  if ((!options.allowTwoLegged) || oauthRequest.token != null) {
    // Must use three-legged-OAuth or the client is using it anyway.
    // The client MUST present a valid access token and the request is valid.

    final accessToken = TokenCredential.lookup(oauthRequest.token);
    if (Verbosity.quiet.index < options.verbosity.index) {
      print('  access token=${oauthRequest.token}'
          ' using ${oauthRequest.signatureMethod}');
    }

    if (accessToken.client.credentials.identifier !=
        client.credentials.identifier) {
      // Section 3.2 of RFC5849 says "the server MAY choose to restrict token
      // usage to the client to which it was issued".
      // Some implementations of a server might not treat this as an error.
      throw BadRequestException('access token does not belong to client');
    }

    oauthRequest.validate(client.credentials, accessToken.secret);

    info = ' resourceOwner="${accessToken.resourceOwner.username}"';
  } else {
    // Two-legged-OAuth: there is no token.
    // Just validating the client had signed the request is sufficient.

    if (Verbosity.quiet.index < options.verbosity.index) {
      print('  two-legged-OAuth request from ${client.name}'
          ' using ${oauthRequest.signatureMethod}');
    }

    oauthRequest.validate(client.credentials);

    info = '';
  }

  checkNonce(oauthRequest);

  // Success: allow access to the resource.

  if (Verbosity.quiet.index < options.verbosity.index) {
    print('  access allowed');
  }

  // Produce response

  final response = request.response;

  response.headers.contentType = ContentType('application', 'json');
  response.write('{"title":"Protected resource",$info'
      ' "being-accessed-by":"${client.name}"}');
  response.close();
}

//----------------------------------------------------------------
/// Handler for the home page.
///
/// Show some information about this example server.

Future<void> handleHomePage(HttpRequest request) async {
  final resp = request.response;

  resp.headers.contentType = ContentType.html;
  resp.write('''<!DOCTYPE html>
<html>
<head>
<title>OAuth1 Example Server</title>
<style type="text/css">
body {
  background: #eee;
  font-family: sans-serif;
}
table.details th {
  text-align: right;
}
td {
  padding: 0ex 1em;
}
</style>
</head>

<body>
<h1>OAuth1 Example Server</h1>

<h2>OAuth1 endpoints</h2>

<p>OAuth1 clients need to be configured to use these URI endpoints, and have
client credentials that are recognised by this server.</p>

<table class="details">
<tr>
  <th>Temporary Credential Request</th>
  <td>http://${hostname(address)}:$port$tmpCredentialRequestUrl</td>
</tr>
<tr>
  <th>Resource Owner Authorization</th>
  <td>http://${hostname(address)}:$port$resourceOwnerAuthUrl</td>
</tr>
<tr>
  <th>Token Request</th>
  <td>http://${hostname(address)}:$port$tokenRequestUrl</td>
</tr>
</table>

</body>
</html>
  ''');

  resp.close();
}

//################################################################
// Command line parsing

/// Verbosity level for information printed.
///
/// Default = 1; quiet = 0; verbose = 2;

enum Verbosity { quiet, normal, verbose, debug }

//----------------

class Arguments {
  /// Constructor from command line arguments

  Arguments(List<String> args) {
    try {
      programName = Platform.script.pathSegments.last.replaceAll('.dart', '');

      final parser = ArgParser(allowTrailingOptions: true)
        ..addFlag('two-legged-oauth',
            abbr: '2', help: 'allow two-legged-OAuth', negatable: false)
        ..addFlag('backdoor',
            abbr: 'B', help: 'enable backdoor verifier', negatable: false)
        ..addFlag('debug',
            abbr: 'D', help: 'show debug information', negatable: false)
        ..addFlag('quiet',
            abbr: 'q', help: 'show less information', negatable: false)
        ..addFlag('verbose',
            abbr: 'v', help: 'show more information', negatable: false)
        ..addFlag('help',
            abbr: 'h', help: 'show this help message', negatable: false);

      final results = parser.parse(args);

      programName = results.name ?? programName;

      // Help flag

      if (results['help']) {
        print(
            'Usage: $programName [options] {client_credential_files}\nOptions:');
        print(parser.usage);
        exit(0);
      }

      allowTwoLegged = results['two-legged-oauth'];

      allowBackdoor = results['backdoor'];

      // Level of output

      if (results['debug']) {
        verbosity = Verbosity.debug;
      } else if (results['verbose']) {
        verbosity = Verbosity.verbose;
      } else if (results['quiet']) {
        verbosity = Verbosity.quiet;
      } else {
        verbosity = Verbosity.normal;
      }

      // Remaining arguments are filenames for client credentials

      for (final filename in results.rest) {
        if (Verbosity.verbose.index < verbosity.index) {
          print('Loading client credentials from "$filename"');
        }
        _loadCredentialsFromFile(filename);
      }
    } on FormatException catch (e) {
      stderr.write('Usage error: $programName: ${e.message}\n');
      exit(2);
    }
  }

  //================================================================
  // Members

  String programName;

  bool allowTwoLegged;

  bool allowBackdoor = false;

  Verbosity verbosity = Verbosity.normal;

  //================================================================
  // Methods

  //----------------------------------------------------------------
  /// Loads client credentials from a file.
  ///
  /// The file may contain zero or more of the following:
  ///
  /// - client identity (property name "oauth_consumer_key")
  /// - shared secret (property name "secret")
  /// - RSA public key (must be in PEM format)
  ///
  /// It must not contain a private key, since an OAuth1 server should not have
  /// access to the client's private key.

  void _loadCredentialsFromFile(String filename) {
    try {
      String name = filename; // defaults to filename if no "name" in file
      String identity; // client's identity
      String sharedSecret;
      String publicKeyText;

      // Parse the file

      int mode = 0;
      StringBuffer buf;

      var lineNum = 0;
      for (final line in File(filename).readAsLinesSync()) {
        lineNum++;
        if (mode == 0) {
          // Normal mode
          if (line.trim().isEmpty || line.trim().startsWith('#')) {
            // comment or blank line: ignore
          } else if (line.startsWith('-----BEGIN RSA PUBLIC KEY-----')) {
            mode = 1; // start capturing lines
            buf = StringBuffer(line)..write('\n');
          } else {
            final pair = line.split(':');
            if (pair.length == 2) {
              final key = pair[0].trim();
              final value = pair[1].trim();
              switch (key) {
                case 'name':
                  name = value;
                  break;
                case 'oauth_consumer_key':
                  identity = value;
                  break;
                case 'secret':
                  sharedSecret = value;
                  break;

                default:
                  stderr.write('$filename: $lineNum: unknown name: $name\n');
                  exit(1);
              }
            } else if (line.contains('BEGIN RSA PRIVATE KEY')) {
              stderr.write(
                  '$filename: $lineNum: private key (servers shouldn\'t have client\'s private key)\n');
              exit(1);
            } else {
              stderr.write('$filename: $lineNum: unexpected line: $line\n');
              exit(1);
            }
          }
        } else if (mode == 1) {
          // Reading private key
          buf..write(line)..write('\n');
          if (line.startsWith('-----END RSA PUBLIC KEY-----')) {
            mode = 0; // finished public key
            publicKeyText = buf.toString();
            buf = null;
          }
        }
      }

      if (mode != 0) {
        stderr.write('$filename: error: incomplete: missing end of key\n');
        exit(1);
      }

      // Check file contained the necessary information

      if (identity == null) {
        stderr.write('$filename: error: no "oauth_consumer_key" in file\n');
        exit(1);
      }
      if (sharedSecret == null && publicKeyText == null) {
        stderr.write('$filename: error: no "secret" or public key in file\n');
        exit(1);
      }

      // Register the client in the server

      registeredClients.add(ClientInfo(name, identity,
          sharedSecret: sharedSecret, pemPublicKey: publicKeyText));
    } catch (e) {
      stderr.write('$filename: $e\n');
      exit(1);
    }
  }
}

//================================================================

Future<void> main(List<String> arguments) async {
  // Command line processing

  options = Arguments(arguments);

  // Output some information about this example server

  final legs = options.allowTwoLegged
      ? 'two-legged-OAuth and three-legged-OAuth'
      : 'three-legged-OAuth only';

  if (Verbosity.quiet.index < options.verbosity.index) {
    print('''OAuth1 Server (supports $legs)

Clients that can request access this server:''');

    for (final c in registeredClients) {
      print('  ${c.name}:');
      print('    Client identity: ${c.credentials.identifier}');
      if (c.credentials.sharedSecret != null) {
        print('      Shared secret: ${c.credentials.sharedSecret}');
      }
      if (c.credentials.publicKey != null) {
        final usage = (c.credentials.sharedSecret != null)
            ? 'is supported for'
            : 'must be used by';
        print('         Public key: yes (RSA-SHA1 $usage this client)');
      }
    }

    print('\nResource owners who can authorize requests for access:');

    for (final owner in resourceOwners) {
      print('  Username: ${owner.username}; password: ${owner.password}');
    }
    print('''

Please run the example client like this:

  dart example_client.dart -s http://${hostname(address)}:$port
''');
  }

  // Run the HTTP server

  final HttpServer server = await HttpServer.bind(address, port);

  await processHttpRequests(server);
}
