OAuth1
======

[![Build Status](https://travis-ci.org/nbspou/dart-oauth1.svg?branch=fork/nbspou)](https://travis-ci.org/nbspou/dart-oauth1)

Library for implementing OAuth1 clients and servers according to OAuth 1a
as defined by [RFC 5849: The OAuth 1.0 Protocol][rfc5849].

Currently only HMAC-SHA1 is supported.

Usage
-----

### OAuth1 client

Here is an example of an OAuth1 client:

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

Once the access token has been obtained, it may be used for multiple
requests.  The client may find it useful to save the access token for
future use, so it doesn't have to go through the three-legged-OAuth
process again. But the usefulness of that will depend on the policy of
the server and if access tokens expire or not.

Also, see the _example_client.dart_ under the _example_ directory.

### OAuth1 server

An OAuth1 server is a HTTP server that issues and manages temporary
credentials and access tokens.

This library can be used to parse the _Authorization_ headers that an
OAuth1 client sends in its HTTP requests to the OAuth1 server. Also
use the library to validate the signature in the _Authorization_
header. If the signature is valid, then the server can use the
properties in the header to issue/manage temporary credentials and
access tokens.

See the _example_server.dart_ under the _example_ directory for how to
use the library to create an OAuth1 server.



[rfc5849]: http://tools.ietf.org/html/rfc5849
