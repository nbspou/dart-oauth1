OAuth1
======

[![Build Status](https://travis-ci.org/nbspou/dart-oauth1.svg?branch=fork/nbspou)](https://travis-ci.org/nbspou/dart-oauth1)

OAuth1 library for implementing OAuth1 clients and OAuth1 servers.

## Supported features

### OAuth 1.0a protocol

This library supports OAuth 1.0 as defined by [RFC 5849: The OAuth 1.0
Protocol][rfc5849].

The RFC 5849 was published in 2010. It addresses errata on the
_OAuth Core 1.0 Revision A_ (also known as OAuth1a) that was published
in 2009. That was a revision of the earlier 2007 specification. This
library does not support OAuth 2.0.

### Signature methods

All the signature methods defined in RFC 5849 are supported:

- HMAC-SHA1;
- RSA-SHA1; and
- PLAINTEXT

### Three-legged-OAuth and two-legged-OAuth

This library can be used to implement three-legged-OAuth, as defined
in the first part of RFC 5849. This is where there are three parties
involved: the client, the resource owner and the server.

1. The _client_ obtains a _temporary credential_ from the _server_;
2. The _resource owner_ authorizes the _server_ to grant the client's
  access request (as identified by the _temporary credential_);
3. The _client_ uses the _temporary credential_ to request a
  _token credential_ from the _server_; and
4. The _client_ accesses protected resources by presenting the _token
  credential_.

It can also be used to implement two-legged-OAuth, which only
involves two parties: the client and the server. The client sends a
single request for the protected resource and the server responds with
it.

## Usage

### OAuth1 client

This library can be used to sign an OAuth1 request. The signed OAuth1
protocol parameters can then be added to a HTTP request and sent to an
OAuth1 server.

Usually, the OAuth1 protocol parameters are sent in a HTTP
"Authorization" header. This library provides a method to format the
parameters for that header. But (less commonly) the parameters can
also be sent as URI query parameters and/or in the body of the HTTP
request.

Here is an example of an OAuth1 client performing three-legged-OAuth:

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
future use, so it does not have to go through the three-legged-OAuth
process again. But the usefulness of that will depend on the policy of
the server and if access tokens expire or not.

An expanded version of the above code appears in the
_example_client.dart_ example.

### OAuth1 server

An OAuth1 server is a HTTP server that implements the endpoints for
processing OAuth1 requests and for accessing the protected resources.

If it implements the three-legged-OAuth protocol, it needs to issues
and manages both temporary credentials and access tokens.  If it
implements the two-legged-OAuth protocol, it only needs to implement
the endpoints for the protected resources (there are no _temporary
credentials_ nor _access tokens_ involved).


This library can be used to parse the information in an OAuth1 HTTP
request and validate the signature. If the signature is valid, then
the server can use the information from the request to perform the
task of the endpoint.

See the _example_server.dart_ for an example of using the library to
create a three-legged-OAuth1 server.


[rfc5849]: http://tools.ietf.org/html/rfc5849
