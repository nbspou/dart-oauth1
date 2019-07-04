/// Example OAuth1a client.
///
/// This client has works with the Twitter OAuth 1a API, using 3-legged OAuth
/// with HMAC-SHA1.
/// https://developer.twitter.com/en/docs/basics/authentication/overview
/// https://tools.ietf.org/html/rfc5849
///
/// It also works with the "example_server.dart" program.
///
/// This client uses an out-of-band mechanism to obtain the verifier (i.e. it
/// asks the resource owner to type in the value) since it does not implement
/// a callback for the server to redirect the browser to.

import 'dart:async';
import 'dart:io';

import 'package:args/args.dart';
import 'package:oauth1/oauth1.dart' as oauth1;

// Dart Linter overrides
// ignore_for_file: always_specify_types

//################################################################
// Constants

// These values have been registered with Twitter as the "dart-oauth1-test" app
// and also hard-coded into the example_server.dart. Therefore, by default this
// client can be used to communicate with Twitter or the example server. But
// other client credentials can be used, by specifying them via the command
// line.

const String defaultServerUri = 'https://api.twitter.com';

const String tmpCredentialRequestUrl = '/oauth/request_token';
const String resourceOwnerAuthUrl = '/oauth/authorize';
const String tokenRequestUrl = '/oauth/access_token';

const String restrictedResourceUrl = '/1.1/statuses/home_timeline.json';

// Default client credentials

const defaultApiKey = 'LLDeVY0ySvjoOVmJ2XgBItvTV';
const defaultApiSecret = 'JmEpkWXXmY7BYoQor5AyR84BD2BiN47GIBUPXn3bopZqodJ0MV';

//################################################################
// Command line parsing

class Arguments {
  Arguments(List<String> args) {
    programName = Platform.script.pathSegments.last.replaceAll('.dart', '');

    final parser = ArgParser(allowTrailingOptions: true)
      ..addOption('credentials', abbr: 'c', help: 'client credentials file')
      ..addOption('server',
          abbr: 's', help: 'base server URI', defaultsTo: defaultServerUri)
      ..addOption('temp-uri',
          abbr: 'T', help: 'temporary credential request URI')
      ..addOption('auth-uri',
          abbr: 'R', help: 'resource owner authorization URI')
      ..addOption('token-uri', abbr: 'A', help: 'access token request URI')
      ..addOption('protected-uri', abbr: 'P', help: 'protected resource URI')
      ..addFlag('debug',
          abbr: 'D', help: 'show debug information', negatable: false)
      ..addFlag('verbose',
          abbr: 'v', help: 'show extra information', negatable: false)
      ..addFlag('help', abbr: 'h', help: 'show this message', negatable: false);

    try {
      final results = parser.parse(args);

      programName = results.name ?? programName;

      // Help flag

      if (_boolOption(results, 'help', false)) {
        print('Usage: $programName [options]');
        print(parser.usage);
        exit(0);
      }

      // Configuration file option

      final credentialFile = _stringOption(results, 'credentials');
      if (credentialFile == null) {
        apiKey = defaultApiKey;
        apiSecret = defaultApiSecret;
      } else {
        // TODO: implement loading client credentials from a file
        throw UnimplementedError(); // will be needed when using RSA keys
      }

      debug = _boolOption(results, 'debug', false);
      verbose = _boolOption(results, 'verbose', false);

      final serverUri = _stringOption(results, 'server', defaultServerUri);

      // Use the URIs provided on the command line, or default to values
      // which are different paths under the server URI.

      uriTemporaryCredentialRequest = _stringOption(
          results, 'temp-uri', '$serverUri$tmpCredentialRequestUrl');
      uriResourceOwnerAuthorization =
          _stringOption(results, 'auth-uri', '$serverUri$resourceOwnerAuthUrl');
      uriTokenRequest =
          _stringOption(results, 'token-uri', '$serverUri$tokenRequestUrl');

      uriProtectedResource = _stringOption(
          results, 'protected-uri', '$serverUri$restrictedResourceUrl');
    } on FormatException catch (e) {
      stderr.write('Usage error: $programName: ${e.message}\n');
      exit(2);
    }
  }

  //================================================================
  // Members

  String programName;

  String uriTemporaryCredentialRequest;
  String uriResourceOwnerAuthorization;
  String uriTokenRequest;
  String uriProtectedResource;

  String apiKey; // client's identity
  String apiSecret; // client's shared secret (for use with HMAC-SHA1)
  String privateKey; // client's private key (for use with RSA-SHA1)

  bool debug;
  bool verbose;

  //================================================================
  // Methods

  //----------------------------------------------------------------

  bool _boolOption(ArgResults results, String optionName, [bool defaultValue]) {
    final Object flag = results[optionName];
    if (flag is bool) {
      return flag;
    } else {
      assert(flag == null);
      return defaultValue;
    }
  }

  //----------------------------------------------------------------

  String _stringOption(ArgResults results, String optionName,
      [String defaultValue]) {
    final Object value = results[optionName];
    if (value is String) {
      return value;
    } else {
      assert(value == null);
      return defaultValue;
    }
  }
}

//################################################################
/// Three-legged-OAuth example.
///
/// Example of a client performing three-legged-OAuth to obtain an access token,
/// which is then used to access a protected resource.

Future<void> threeLeggedOAuth(
    oauth1.ClientCredentials clientCredentials,
    oauth1.Authorization auth,
    oauth1.SignatureMethod signatureMethod,
    String protectedResourceUri,
    {bool verbose,
    bool debug}) async {
  //----------------
  // Step 1: request temporary credentials from the server
  //
  // If this client was a Web application, it would provide a callback URL
  // with the request. But in this non-browser example, the request indicates an
  // out-of-band ("oob") mechanism will be used.

  final oauth1.AuthorizationResponse res1 =
      await auth.requestTemporaryCredentials('oob');

  if (debug) {
    print('OAuth 1a temporary credentials:\n  ${res1.credentials}');
  }

  //----------------
  // Step 2: get the resource owner to approve the temporary credentials
  //
  // If this client was a Web application, it would redirect the browser to
  // the server's Resource Owner Authorization endpoint. And if the approval is
  // given, the server will redirect the browser to the callback URL - providing
  // this client the approval.
  //
  // In this non-browser example, print out the URL for the user to visit.
  // Since the temporary credential uses an out-of-band mechanism, the server
  // will provide the user a PIN code which they will have to manually provide
  // to this client.

  final String url =
      auth.getResourceOwnerAuthorizationURI(res1.credentials.token);
  print('Please open this URL in a browser:\n  $url');

  // This client obtains the verifier (PIN)

  stdout.write('PIN: ');
  final String verifier = stdin.readLineSync();
  if (verifier == null) {
    stderr.write('aborted\n');
    exit(1);
  }

  //----------------
  // Step 3: get access token from the server.
  //
  // Obtains an access token from the server.

  // request token credentials (access tokens)

  final oauth1.AuthorizationResponse res2 =
      await auth.requestTokenCredentials(res1.credentials, verifier);

  if (debug) {
    print('OAuth 1a access token credentials:\n  ${res2.credentials}');
  }

  //----------------
  // Step 4: use the access token to access protected resources

  final oauth1.Client client =
      oauth1.Client(signatureMethod, clientCredentials, res2.credentials);

  // now you can access to protected resources via client

  final res3 = await client.get(protectedResourceUri);

  if (verbose) {
    print('Body of protected resource:\n  ${res3.body}');
  }

  // NOTE: you can get optional values from AuthorizationResponse object
  final name = res2.optionalParameters['screen_name'];

  print('\nSuccess: client has access to the protected resources of "$name".');
}

//----------------------------------------------------------------

Future<void> main(List<String> arguments) async {
  // Process command line arguments

  final args = Arguments(arguments);

  // Define the platform (i.e. the server)

  final oauth1.Platform platform = oauth1.Platform(
      args.uriTemporaryCredentialRequest,
      args.uriResourceOwnerAuthorization,
      args.uriTokenRequest,
      oauth1.SignatureMethods.hmacSha1);

  // Define the credentials for this client (i.e. the identity previously
  // established by the client with the server, plus the shared secret
  // for HMAC-SHA1 or RSA private key for RSA-SHA1).

  final oauth1.ClientCredentials clientCredentials =
      oauth1.ClientCredentials(args.apiKey, args.apiSecret);

  // Create Authorization object with client credentials and the platform

  final oauth1.Authorization auth =
      oauth1.Authorization(clientCredentials, platform);

  // Use the Authorization object to perform three-legged-OAuth

  await threeLeggedOAuth(clientCredentials, auth,
      oauth1.SignatureMethods.hmacSha1, args.uriProtectedResource,
      verbose: args.verbose, debug: args.debug);
}
