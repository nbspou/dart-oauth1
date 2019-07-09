OAuth1 Examples
===============

## Introduction

These examples demonstrate the use of the oauth1 library to
implement an OAuth client and an OAuth server.

## Running the examples

1. Run the example OAuth server:

        dart example_server.dart

2. In a different terminal, run the client with the URL of the server:

        dart example_client.dart -s http://localhost:8080

3. Open the URL printed by the client and authorize the client using
   the username "armstrong" and password of "password".

4. Type the PIN from the Web page into the client.

5. The client should print out a message indicating it has successfully
   accessed the protected resource.

## Changing behaviour

### Using other signing methods

The example client's default signature method is HMAC-SHA1.
Use the following options to change the signature method:

- `--rsa-sha1` (`-r`) to use the RSA-SHA1 signature method;
- `--plaintext` (`-p`) to use the PLAINTEXT signature method.

The server is capable of using any of the signing methods, as long as
the client credentials it has are suitable. That is, it has a shared
secret for HMAC-SHA1 and PLAINTEXT, or it has an RSA public key for
RSA-SHA1.

### Using other credentials

The client and server both have hard-coded credentials. The default
hard-coded credentials are suitable for all three signature methods.

#### Server

For the server to know about other client credentials, run the server
and provide credential files as additional arguments. Multiple files
can be provided. For example,

    dart example_server.dart tester1.secret tester2.public 

#### Client

For the client to use another client credential, specify the
credentials file using the `--credentials` (`-c`) option:

```sh
dart example_client.dart -s http://localhost:8080 -c tester2.private --rsa-sha1
```

The client identity can also be specified using the `--client` option,
otherwise it must be specified inside the credentials file.  Note:
this only applies to the example client: the credentials file for the
example server must include the client identity (since more than one
credentials files can be registered with the server).

#### Credentials file

A credentials file can contain:

- a user friendly name for the client (as "name");
- client identifier (as "oauth_consumer_key");
- shared secret (as "secret");
- PEM formatted RSA private key; and/or
- PEM formatted RSA public key.

See the example tester credentials files for the expected syntax.

Only PEM formatted RSA public/private keys are recognised.

Note: the client credentials file for the server must not contain an
an RSA private key, since the OAuth server should not have the
client's private key.

### Showing more information

Use the `--verbose` (`-v`) option on the example client and example
server.

### Testing without the manual authorization step

Both the server and client have a `--backdoor` (`-B`) option to make
them easier to test.

Enabling it on both client and server causes the client to
automatically submit a backdoor value for the PIN verifier, which
causes the server to automatically approve the request (as if a
_resource owner_ had visited the Web page and approved the client's
request) and continue to accept the verifier as correct. This avoids
the need to interact with the Web browser to obtain the PIN.

This feature is for testing only. Obviously, a production OAuth server
should not have a backdoor.

### Two-legged-OAuth

The default behaviour is to perform three-legged-OAuth.

To use two-legged-OAuth, run both the example server and example
client with the `--two-legged-oauth` (`-2`) option.

### Testing against other OAuth servers

The example client has options to customise the server endpoints for
the OAuth1 protocol.

The `--server` (`-s`) is a short-hand for setting all three OAuth1
protocol endpoints plus one protected resource endpoint. It assumes
hard-coded paths under that URL. Those hard-coded paths match those
hard-coded in the example server as well as the Twitter API
(i.e. _/oauth/request_token_, _/oauth/authorize_,
_/oauth/access_token_ and _/1.1/statuses/home_timeline.json_).

If those hard-coded parths are not suitable, the full endpoint URLs
can be specified using these options:

- `--temp-uri` (`-T`) for the temporary credential requset URI;
- `--auth-uri` (`-R`) for the resource owner authorization URI;
- `--token-uri` (`-A`) for the (access) token request URI; and
- one or more protected resource URIs as additional arguments.

The default behaviour, if none of these options are used, is to
contact the Twitter API.

