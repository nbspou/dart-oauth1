OAuth1
===========

[![Build Status](https://travis-ci.org/nbspou/dart-oauth1.svg?branch=fork/nbspou)](https://travis-ci.org/nbspou/dart-oauth1)

"[RFC 5849: The OAuth 1.0 Protocol][rfc5849]" client implementation for dart

Usage
-----

Add to `pubspec.yaml`:

```yaml
dependencies:
  oauth1: ^1.0.4
```

Please use like below.

```dart
import 'dart:io';
import 'package:oauth1/oauth1.dart' as oauth1;

void main() {
  // define platform (server)
  var platform = new oauth1.Platform(
      'https://api.twitter.com/oauth/request_token', // temporary credentials request
      'https://api.twitter.com/oauth/authorize',     // resource owner authorization
      'https://api.twitter.com/oauth/access_token',  // token credentials request
      oauth1.SignatureMethods.hmacSha1              // signature method
      );

  // define client credentials (consumer keys)
  const String apiKey = 'LLDeVY0ySvjoOVmJ2XgBItvTV';
  const String apiSecret = 'JmEpkWXXmY7BYoQor5AyR84BD2BiN47GIBUPXn3bopZqodJ0MV';
  var clientCredentials = new oauth1.ClientCredentials(apiKey, apiSecret);

  // create Authorization object with client credentials and platform definition
  var auth = new oauth1.Authorization(clientCredentials, platform);

  // request temporary credentials (request tokens)
  auth.requestTemporaryCredentials('oob').then((res) {
    // redirect to authorization page
    print("Open with your browser: ${auth.getResourceOwnerAuthorizationURI(res.credentials.token)}");

    // get verifier (PIN)
    stdout.write("PIN: ");
    String verifier = stdin.readLineSync();

    // request token credentials (access tokens)
    return auth.requestTokenCredentials(res.credentials, verifier);
  }).then((res) {
    // yeah, you got token credentials
    // create Client object
    var client = new oauth1.Client(platform.signatureMethod, clientCredentials, res.credentials);

    // now you can access to protected resources via client
    client.get('https://api.twitter.com/1.1/statuses/home_timeline.json?count=1').then((res) {
      print(res.body);
    });

    // NOTE: you can get optional values from AuthorizationResponse object
    print("Your screen name is " + res.optionalParameters['screen_name']);
  });
}

```

In addition, You should save and load the granted token credentials from your drive. Of cource, you don't need to authorize when you did it.

[rfc5849]: http://tools.ietf.org/html/rfc5849
