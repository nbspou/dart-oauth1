import 'dart:convert';

import 'package:oauth1/oauth1.dart' as prefix0;
import 'package:test/test.dart';
import 'package:oauth1/oauth1.dart';
import 'package:encrypt/encrypt.dart';

//################################################################

void main() {
  group('signature base string', () {
    //================================================================

    group('example from section 3.4.1.1 of RFC 5849', () {
      // Tests the "signature base string" matches the example value from
      // Section 3.4.1.1 of RFC 5849
      // <https://tools.ietf.org/html/rfc5849#section-3.4.1>

      const String expectedSBS =
          'POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q'
          '%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_'
          'key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m'
          'ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk'
          '9d7dh3k39sjv7';

      final AuthorizationRequest req = AuthorizationRequest();
      req.add(AuthorizationRequest.oauth_consumer_key, '9djdj82h48djs9d2');
      req.add(AuthorizationRequest.oauth_signature_method, 'HMAC-SHA1');
      req.add(AuthorizationRequest.oauth_nonce, '7d8f3e4a');
      req.add(AuthorizationRequest.oauth_signature,
          'bYT5CMsGcbgUdFHObYMEfcx6bsw%3D');

      req.add('c2', '');
      req.add('a3', '2 q'); // Note: URI's query parameters also has an "a3"

      const Credentials tokenCredentials =
          Credentials('kkk9d7dh3k39sjv7', 'someSharedSecret');

      const String method = 'POST';
      final Uri uri = Uri.parse(
          'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b');

      final ClientCredentials clientCredentials =
          ClientCredentials('9djdj82h48djs9d2', 'someotherSecret');

      const int exampleTimestamp = 137131201;
      const String exampleNonce = '7d8f3e4a';

      //----------------------------------------------------------------

      test('string construction for creating signature', () {
        final String signatureBaseString = req.sign(
            method, uri, clientCredentials, SignatureMethods.hmacSha1,
            tokenCredentials: tokenCredentials,
            timestamp: exampleTimestamp,
            nonce: exampleNonce);

        expect(signatureBaseString, equals(expectedSBS));
      });

      //----------------------------------------------------------------

      test('string construction for signature validation', () {
        // The token_secret is not correct, so signature validation will fail.
        // But this test only cares about whether the calculated signature base
        // string has the expected value.

        try {
          req.validate(clientCredentials, 'wrongSecret');
          fail('validated using the wrong secret');
        } on SignatureInvalid catch (e) {
          // This will occur, since the wrong secret is used
          expect(e.signatureBaseString, equals(expectedSBS));
        }
      });
    });

    //----------------------------------------------------------------

    test('example from section 3.4.1.3.2 of RFC 5849', () {
      final AuthorizationRequest req = AuthorizationRequest();

      req.addAll(Uri.splitQueryString('c2&a3=2+q').map(
          (String name, String value) =>
              MapEntry<String, List<String>>(name, [value])));

      final String signatureBaseString = req.sign(
          'POST',
          Uri.parse(
              'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b'),
          ClientCredentials('9djdj82h48djs9d2', 'secret'),
          SignatureMethods.hmacSha1,
          tokenCredentials:
              const Credentials('kkk9d7dh3k39sjv7', 'anotherSecret'),
          timestamp: 137131201,
          nonce: '7d8f3e4a');

      // Check fully decoded parameters match those shown in section 3.4.1.3.1.

      expect(req.parameters['b5'].first, equals('=%3D'));
      expect(req.parameters['a3'].contains('a'), isTrue);
      expect(req.parameters['c@'].first, equals(''));
      expect(req.parameters['a2'].first, equals('r b'));
      expect(req.parameters['oauth_consumer_key'].first,
          equals('9djdj82h48djs9d2'));
      expect(req.parameters['oauth_token'].first, equals('kkk9d7dh3k39sjv7'));
      expect(
          req.parameters['oauth_signature_method'].first, equals('HMAC-SHA1'));
      expect(req.parameters['oauth_timestamp'].first, equals('137131201'));
      expect(req.parameters['oauth_nonce'].first, equals('7d8f3e4a'));
      expect(req.parameters['c2'].first, equals(''));
      expect(req.parameters['a3'].contains('2 q'), isTrue);
      expect(req.parameters.length, equals(11));

      const String expectedNormalizedParams =
          'a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj'
          'dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1'
          '&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7';

      // Extract the normalized parameters part from the signature base string

      final parts = signatureBaseString.split('&');
      final String encoded = parts[2];
      final List<int> bytes = <int>[];

      int x = 0;
      while (x < encoded.length) {
        final int code = encoded.codeUnitAt(x);
        if (code != 0x25) {
          // not "%"
          bytes.add(code);
          x++;
        } else {
          // "%XX"
          bytes.add(int.parse(encoded.substring(x + 1, x + 3), radix: 16));
          x += 3;
        }
      }

      final String decoded = String.fromCharCodes(bytes);

      expect(decoded, equals(expectedNormalizedParams));
    });

    //----------------------------------------------------------------

    test('encoding parameter values', () {
      final AuthorizationRequest req = AuthorizationRequest();
      req.set('example-asterisk', '_*_');
      req.set('example-space', '_ _');
      req.set('example-reserved', '_ABCDabcd0123456789-._~');
      req.set('name-._~ _*_%_012345', 'names-are-encoded-too');

      final String signatureBaseString = req.sign(
          'post',
          Uri.parse('HTTP://EXAMPLE.COM:80'),
          ClientCredentials('tester', 'secret'),
          SignatureMethods.plaintext,
          timestamp: 1,
          nonce: 'abcdefgh');

      expect(
          signatureBaseString,
          equals('POST&http%3A%2F%2Fexample.com&'
              'example-asterisk%3D_%252A_%26'
              'example-reserved%3D_ABCDabcd0123456789-._~%26'
              'example-space%3D_%2520_%26'
              'name-._~%2520_%252A_%2525_012345%3Dnames-are-encoded-too%26'
              'oauth_consumer_key%3Dtester%26'
              'oauth_nonce%3Dabcdefgh%26'
              'oauth_signature_method%3DPLAINTEXT%26'
              'oauth_timestamp%3D1'));
    });
  });

  //================================================================

  group('sign, encode, parse and validate', () {
    final Uri testUri = Uri.parse('HTTPS://Example.COM/Abc/Def');

    const String clientId = 'client1';
    const String clientSharedSecret = 'secretValue';

    final RSAKeyParser keyParser = RSAKeyParser();

    final ClientCredentials clientCredentials = ClientCredentials(
        clientId, clientSharedSecret,
        privateKey: keyParser.parse(pemPrivateKey),
        publicKey: keyParser.parse(pemPublicKey));

    const String testTokenId = 'foo';
    const String testTokenSecret = 'bar';

    const Credentials tokenCredentials =
        Credentials(testTokenId, testTokenSecret);

    const int testTimestamp = 1;
    const String testNonce = 'abcdef';

    const String testRealm = 'https://realm.example.com';

    //----------------------------------------------------------------

    test('HMAC-SHA1 without token', () {
      // Create signed OAuth request

      String authHeader;
      {
        final AuthorizationRequest req1 = AuthorizationRequest();
        req1.sign('post', testUri, clientCredentials, SignatureMethods.hmacSha1,
            timestamp: testTimestamp, nonce: testNonce);

        // Check for expected parameters

        // print(req1);

        expect(req1.clientIdentifier, equals(clientId));
        expect(req1.timestamp, equals(testTimestamp.toString()));
        expect(req1.nonce, equals(testNonce));
        expect(req1.signatureMethod, equals('HMAC-SHA1'));
        expect(req1.signature, 'wEpcEetuMDVjzIPJBD2XXUrNdx0=');
        expect(req1.version, isNull);
        expect(req1.callback, isNull);
        expect(req1.verifier, isNull);
        expect(req1.token, isNull); // no tokenCredential passed to sign

        expect(req1.parameters.length, equals(5)); // all parameters
        expect(req1.oauthParams().length, equals(5)); // OAuth parameters

        expect(req1.method, equals('POST')); // method converted to uppercase
        // Domain is lowercase, but case in path is preserved
        expect(req1.uri.toString(), equals('https://example.com/Abc/Def'));

        // Encode

        authHeader = req1.headerValue(realm: testRealm);
      }

      expect(authHeader,
          startsWith('OAuth realm="https%3A%2F%2Frealm.example.com",'));

      // Parse

      final AuthorizationRequest req2 = AuthorizationRequest.fromHttpRequest(
          'pOsT', // case insensitive
          testUri,
          <String>[
            'SomeScheme foo="bar"', // non-OAuth scheme headers will be ignored
            authHeader,
            'OAuthX foo="bar"', // this is also a non-OAuth scheme header
          ],
          null);

      expect(req2.clientIdentifier, equals(clientId));
      expect(req2.timestamp, equals(testTimestamp.toString()));
      expect(req2.nonce, equals(testNonce));
      expect(req2.signatureMethod, equals('HMAC-SHA1'));
      expect(req2.signature, 'wEpcEetuMDVjzIPJBD2XXUrNdx0=');
      expect(req2.version, isNull);
      expect(req2.callback, isNull);
      expect(req2.verifier, isNull);
      expect(req2.token, isNull); // no tokenCredential passed to sign

      expect(req2.parameters.length, equals(5)); // all parameters
      expect(req2.oauthParams().length, equals(5)); // OAuth parameters

      expect(req2.method, equals('POST'));
      expect(req2.uri.toString(), equals('https://example.com/Abc/Def'));

      // Validate

      req2.validate(clientCredentials);

      final List<String> realms = req2.realms;
      expect(realms.length, equals(1)); // only one OAuth scheme header value
      expect(realms[0], equals(testRealm));

      //expect(signatureBaseString, equals(expectedSBS));
    });

    //----------------------------------------------------------------

    test('PLAINTEXT with token', () {
      // Create signed OAuth request

      String signatureBaseStringSigned;
      String authHeader;
      {
        final AuthorizationRequest req1 = AuthorizationRequest();

        // Set the optional oauth_version
        req1.set(AuthorizationRequest.oauth_version,
            AuthorizationRequest.supportedVersion);

        signatureBaseStringSigned = req1.sign(
            'PosT', testUri, clientCredentials, SignatureMethods.plaintext,
            tokenCredentials: tokenCredentials,
            timestamp: testTimestamp,
            nonce: testNonce);

        // Check for expected parameters

        // print(req1);

        expect(req1.clientIdentifier, equals(clientId));
        expect(req1.timestamp, equals(testTimestamp.toString()));
        expect(req1.nonce, equals(testNonce));
        expect(req1.signatureMethod, equals('PLAINTEXT'));
        expect(req1.signature, '$clientSharedSecret&$testTokenSecret');
        expect(req1.version, '1.0');
        expect(req1.callback, isNull);
        expect(req1.verifier, isNull);
        expect(req1.token, testTokenId);

        expect(req1.parameters.length, equals(7)); // all parameters
        expect(req1.oauthParams().length, equals(7)); // OAuth parameters

        expect(req1.method, equals('POST')); // method converted to uppercase
        // Domain is lowercase, but case in path is preserved
        expect(req1.uri.toString(), equals('https://example.com/Abc/Def'));

        // Encode

        authHeader = req1.headerValue(realm: testRealm);
      }

      expect(authHeader,
          startsWith('OAuth realm="https%3A%2F%2Frealm.example.com",'));

      // Parse

      final AuthorizationRequest req2 = AuthorizationRequest.fromHttpRequest(
          'post', // case insensitive
          testUri,
          <String>[
            'SomeScheme foo="bar"', // non-OAuth scheme headers will be ignored
            authHeader,
            'OAuthX foo="bar"', // this is also a non-OAuth scheme header
          ],
          null);

      expect(req2.clientIdentifier, equals(clientId));
      expect(req2.timestamp, equals(testTimestamp.toString()));
      expect(req2.nonce, equals(testNonce));
      expect(req2.signatureMethod, equals('PLAINTEXT'));
      expect(req2.signature, '$clientSharedSecret&$testTokenSecret');
      expect(req2.version, AuthorizationRequest.supportedVersion);
      expect(req2.callback, isNull);
      expect(req2.verifier, isNull);
      expect(req2.token, testTokenId);

      expect(req2.parameters.length, equals(7)); // all parameters
      expect(req2.oauthParams().length, equals(7)); // OAuth parameters

      expect(req2.method, equals('POST'));
      expect(req2.uri.toString(), equals('https://example.com/Abc/Def'));

      // Validate

      try {
        req2.validate(clientCredentials, tokenCredentials.tokenSecret);
      } on SignatureInvalid catch (e) {
        // print(signatureBaseStringSigned);
        // print(e.signatureBaseString);
        expect(e.signatureBaseString, equals(signatureBaseStringSigned),
            reason: 'invalid because signature base strings are not the same');
        fail('invalid for some other reason');
      }

      final List<String> realms = req2.realms;
      expect(realms.length, equals(1)); // only one OAuth scheme header value
      expect(realms[0], equals(testRealm));

      //expect(signatureBaseString, equals(expectedSBS));
    });

    //----------------------------------------------------------------

    test('RSA-SHA1 with token and other parameters', () {
      // Create signed OAuth request

      String signatureBaseStringSigned;
      String authHeader;
      {
        final AuthorizationRequest req1 = AuthorizationRequest();

        req1.set('a', 'b');
        req1.add('foo', 'bar');
        req1.add('foo', 'baz');
        req1.addAll(<String, Iterable<String>>{
          'alphabet': <String>['alpha', 'beta', 'gamma']
        });

        signatureBaseStringSigned = req1.sign(
            'GET', testUri, clientCredentials, SignatureMethods.rsaSha1,
            tokenCredentials: tokenCredentials,
            timestamp: testTimestamp,
            nonce: testNonce);

        // Check for expected parameters

        // print(req1);

        expect(req1.clientIdentifier, equals(clientId));
        expect(req1.timestamp, equals(testTimestamp.toString()));
        expect(req1.nonce, equals(testNonce));
        expect(req1.signatureMethod, equals('RSA-SHA1'));
        expect(
            req1.signature,
            'jy6wd1niBBz6TrkcbppUhc3txZZJb1wYL5XM09+6GzRZCl3EW8OST9PWnWAJ34pRWq'
            '6rYaRSo9Ig55NEWJ1l72Sc/Ck8a54HuLRbjEBLCSBOdy0x8lcCa1EHa8nc5pbtmoaV'
            '9LztE6Y35PQNxnNa6azZ7J1dwC8ZWejG404XlfGPveC4JncUooPh7YZ+h69kH3kOrD'
            'zK7xA/DoIMsQrE41jKmmWo2MlzpfKpGJjR1wkbPej72tLxk2jSHzHd0a8L6HmY6ZoG'
            'TYlZ9o0WMB2hbAn25sCOAgnFcy7wvBaUydJCVJfVjdAN7U0OOkThIPpIelX8BVzWwE'
            'BpEErxwaCanxd1Q/qKjFAkfi6IcYEMy+1AXOvTF18iML2G+8tLZEb05I211JQH6qna'
            'DQQUdAa0vxeBVrxDuWhCA9U36cPs04DWlhUYfWY7U+y6uNTzamheU002EgoRrRPsCH'
            'tWC7ksM0nKsH5uIYcp6GrRd13W44GfTTaFTITlr78SZebIavhVz+gvYPVqGT2RRsi9'
            'goifRN91eXItvPADr3f8HB8lbEd4kKq282olI46tv4dwnhY/91K/evMAQyuCdjKnEc'
            '24Ps13uO7aXUCwZhn2nL/lEVSvMxRvM9l01gU48dUNKFO74YAbGCJLadprLISnC9tQ'
            'J3qIfItQeLnhFnm29fuK6Og=');
        expect(req1.version, isNull);
        expect(req1.callback, isNull);
        expect(req1.verifier, isNull);
        expect(req1.token, testTokenId);

        expect(req1.parameters.length, equals(9)); // all parameters
        expect(req1.oauthParams().length, equals(6)); // OAuth parameters

        expect(req1.method, equals('GET'));
        // Domain is lowercase, but case in path is preserved
        expect(req1.uri.toString(), equals('https://example.com/Abc/Def'));

        expect(req1.get('a').length, equals(1));
        expect(req1.get('foo').length, equals(2));
        expect(req1.get('alphabet').length, equals(3));

        // Encode

        authHeader = req1.headerValue(realm: testRealm);
      }

      expect(authHeader,
          startsWith('OAuth realm="https%3A%2F%2Frealm.example.com",'));

      // Parse
      //
      // Note: non-OAuth parameters are assumed to have been transmitted as
      // query parameters and in the url-encoded body.

      final AuthorizationRequest req2 = AuthorizationRequest.fromHttpRequest(
          'get', // case insensitive
          Uri(
              scheme: testUri.scheme,
              host: testUri.host,
              path: testUri.path,
              query: 'alphabet=gamma&foo=baz'), // testUri with extra parameters
          <String>[authHeader],
          'a=b&foo=bar&alphabet=alpha&alphabet=beta');

      expect(req2.clientIdentifier, equals(clientId));
      expect(req2.timestamp, equals(testTimestamp.toString()));
      expect(req2.nonce, equals(testNonce));
      expect(req2.signatureMethod, equals('RSA-SHA1'));
      expect(base64.decode(req2.signature).length, equals(512));
      expect(req2.version, isNull);
      expect(req2.callback, isNull);
      expect(req2.verifier, isNull);
      expect(req2.token, testTokenId);

      expect(req2.parameters.length, equals(9)); // all parameters
      expect(req2.oauthParams().length, equals(6)); // OAuth parameters

      expect(req2.method, equals('GET'));
      expect(req2.uri.toString(), equals('https://example.com/Abc/Def'));

      expect(req2.get('a').length, equals(1));
      expect(req2.get('foo').length, equals(2));
      expect(req2.get('alphabet').length, equals(3));

      // Validate

      req2.validate(clientCredentials);

      final List<String> realms = req2.realms;
      expect(realms.length, equals(1)); // only one OAuth scheme header value
      expect(realms[0], equals(testRealm));

      // Tampering with any of the parameters will invalidate the signature

      req2.set('a', 'B'); // changed value from 'b' to 'B'.
      try {
        req2.validate(clientCredentials);
        fail('tampered value still validates');
      } on SignatureInvalid catch (e) {
        // Invalid because the signature base string is now different
        expect(e.signatureBaseString, isNot(equals(signatureBaseStringSigned)));
      }
    });
  });
}

//################################################################
// RSA public and private keys

const String pemPublicKey = '''
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
      ''';

const String pemPrivateKey = '''
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
''';
