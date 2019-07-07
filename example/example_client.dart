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
import 'package:encrypt/encrypt.dart';
import 'package:oauth1/oauth1.dart' as oauth1;
import 'package:pointycastle/asymmetric/api.dart';

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

const defaultClientIdentity = 'LLDeVY0ySvjoOVmJ2XgBItvTV';
const defaultSecret = 'JmEpkWXXmY7BYoQor5AyR84BD2BiN47GIBUPXn3bopZqodJ0MV';

const defaultPrivateKey = '''
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
''';

//################################################################
// Command line parsing

class Arguments {
  Arguments(List<String> args) {
    programName = Platform.script.pathSegments.last.replaceAll('.dart', '');

    final parser = ArgParser(allowTrailingOptions: true)
      ..addOption('server',
          abbr: 's', help: 'base server URI', defaultsTo: defaultServerUri)
      ..addOption('credentials', abbr: 'c', help: 'client credentials file')
      ..addOption('client',
          abbr: 'C',
          help: 'client identity (a.k.a. oauth_consumer_key or API key)')
      ..addFlag('rsa-sha1',
          abbr: 'r',
          help: 'sign with RSA-SHA1 signature method (default: HMAC-SHA1)',
          negatable: false)
      ..addFlag('plaintext',
          abbr: 'p',
          help: 'sign with PLAINTEXT signature method (default: HMAC-SHA1)',
          negatable: false)
      ..addOption('temp-uri',
          abbr: 'T', help: 'URI for temporary credential request *')
      ..addOption('auth-uri',
          abbr: 'R', help: 'URI for resource owner authorization *')
      ..addOption('token-uri',
          abbr: 'A', help: 'URI for access token request *')
      ..addOption('protected-uri',
          abbr: 'P', help: 'URI for the protected resource *')
      ..addFlag('backdoor',
          abbr: 'B',
          help: 'use backdoor verifier (only for the example_server.dart)',
          negatable: false)
      ..addFlag('debug',
          abbr: 'D', help: 'show debug information', negatable: false)
      ..addFlag('verbose',
          abbr: 'v', help: 'show more information', negatable: false)
      ..addFlag('help',
          abbr: 'h', help: 'show this help message', negatable: false);

    try {
      final results = parser.parse(args);

      programName = results.name ?? programName;

      // Help flag

      if (results['help']) {
        print('Usage: $programName [options]');
        print(parser.usage);
        print('* defaults to paths relative to the base server URI.');
        exit(0);
      }

      // Signature method

      if (results['rsa-sha1']) {
        signatureMethod = oauth1.SignatureMethods.rsaSha1;
      } else if (results['plaintext']) {
        signatureMethod = oauth1.SignatureMethods.plaintext;
      } else {
        signatureMethod = oauth1.SignatureMethods.hmacSha1; // default
      }

      // Credentials file option

      final keyParser = RSAKeyParser();

      final credentialFile = _stringOption(results, 'credentials');
      if (credentialFile == null) {
        clientIdentity = defaultClientIdentity;
        sharedSecret = defaultSecret;
        privateKey = keyParser.parse(defaultPrivateKey);
      } else {
        _loadCredentialsFromFile(keyParser, credentialFile);
      }
      final c = _stringOption(results, 'client');
      if (c != null) {
        clientIdentity = c;
      }

      useBackdoor = results['backdoor'];
      debug = results['debug'];
      verbose = results['verbose'];

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

  oauth1.SignatureMethod signatureMethod;

  String clientIdentity; // client's identity
  String sharedSecret; // client's shared secret (for HMAC-SHA1 or PLAINTEXT)
  RSAPrivateKey privateKey; // client's private key (for RSA-SHA1)

  bool useBackdoor;
  bool debug;
  bool verbose;

  //================================================================
  // Methods

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

  //----------------------------------------------------------------
  /// Loads client credentials from a file.
  ///
  /// The file may contain zero or more of the following:
  ///
  /// - client identity (property name "oauth_consumer_key")
  /// - shared secret (property name "secret")
  /// - RSA private key (must be in PEM format)
  ///
  /// It is OK for there to be no client identity in the file, since it can
  /// alternatively be provided as a command line option.

  void _loadCredentialsFromFile(RSAKeyParser keyParser, String filename) {
    try {
      // Parse the file

      int mode = 0; // 0=normal, 1=reading-private-key, 2=reading-public-key
      StringBuffer buf;
      var seenPublicKey = false;

      var lineNum = 0;
      for (final line in File(filename).readAsLinesSync()) {
        lineNum++;
        if (mode == 0) {
          // Normal mode
          if (line.trim().isEmpty || line.trim().startsWith('#')) {
            // comment or blank line: ignore
          } else if (line.startsWith('-----BEGIN RSA PRIVATE KEY-----')) {
            mode = 1; // start capturing lines
            buf = StringBuffer(line)..write('\n');
          } else {
            final pair = line.split(':');
            if (pair.length == 2) {
              final name = pair[0].trim();
              final value = pair[1].trim();
              switch (name) {
                case 'name':
                  // Names are not used in the client
                  break;
                case 'oauth_consumer_key':
                  clientIdentity = value;
                  break;
                case 'secret':
                  sharedSecret = value;
                  break;

                default:
                  stderr.write('$filename: $lineNum: unknown name: $name\n');
                  exit(1);
              }
            } else if (line.contains('BEGIN RSA PUBLIC KEY')) {
              mode = 2;
            } else {
              stderr.write('$filename: $lineNum: unexpected line: $line\n');
              exit(1);
            }
          }
        } else if (mode == 1) {
          // Reading private key
          buf..write(line)..write('\n');
          if (line.startsWith('-----END RSA PRIVATE KEY-----')) {
            mode = 0; // finished private key
            privateKey = keyParser.parse(buf.toString());
            buf = null;
          }
        } else if (mode == 2) {
          // Reading public key (and discarding it)
          if (line.startsWith('-----END RSA PUBLIC KEY-----')) {
            mode = 0; // finished public key
            seenPublicKey = true;
          }
        }
      }

      if (mode != 0) {
        stderr.write('$filename: error: incomplete: missing end of key\n');
        exit(1);
      }

      // Check file contained the necessary information

      if (sharedSecret == null && privateKey == null) {
        stderr.write('$filename: error: no "secret" or private key in file\n');
        if (seenPublicKey) {
          stderr.write('  The file has a public key, but no private key.\n');
        }
        exit(1);
      }
    } catch (e) {
      stderr.write('$filename: $e\n');
      exit(1);
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
    bool useBackdoor,
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

  String verifier;

  if (!useBackdoor) {
    stdout.write('PIN: ');
    verifier = stdin.readLineSync();
    if (verifier == null || verifier.isEmpty) {
      stderr.write('aborted\n');
      exit(1);
    }
  } else {
    // This is to make it easy to test with the example_client.dart. It uses
    // a verifier that automatically makes the temporary token approved, without
    // having to visit the Web page. Obviously, a production server should not
    // have any backdoors!
    verifier = 'backdoor';
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

  try {
    // Define the platform (i.e. the server)

    final oauth1.Platform platform = oauth1.Platform(
        args.uriTemporaryCredentialRequest,
        args.uriResourceOwnerAuthorization,
        args.uriTokenRequest,
        args.signatureMethod);

    // Define the credentials for this client (i.e. the identity previously
    // established by the client with the server, plus the shared secret
    // for HMAC-SHA1 or RSA public and private keys for RSA-SHA1).

    final oauth1.ClientCredentials clientCredentials = oauth1.ClientCredentials(
        args.clientIdentity, args.sharedSecret,
        privateKey: args.privateKey);

    // Create Authorization object with client credentials and the platform

    final oauth1.Authorization auth =
        oauth1.Authorization(clientCredentials, platform);

    // Use the Authorization object to perform three-legged-OAuth

    await threeLeggedOAuth(clientCredentials, auth, args.signatureMethod,
        args.uriProtectedResource,
        verbose: args.verbose,
        useBackdoor: args.useBackdoor,
        debug: args.debug);
  } catch (e) {
    if (args.verbose) {
      rethrow;
    }
    stderr.write('Error: $e\n');
    exit(1);
  }
}
