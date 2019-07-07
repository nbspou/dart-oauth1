import 'package:test/test.dart';
import 'package:oauth1/oauth1.dart';

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

      final AuthorizationHeader auth = AuthorizationHeader.empty();

      auth['realm'] = 'Example'; // this won't appear in signature base string
      auth[AuthorizationHeader.oauth_consumer_key] = '9djdj82h48djs9d2';
      auth[AuthorizationHeader.oauth_token] = 'kkk9d7dh3k39sjv7';
      auth[AuthorizationHeader.oauth_signature_method] = 'HMAC-SHA1';
      auth[AuthorizationHeader.oauth_nonce] = '7d8f3e4a';
      auth[AuthorizationHeader.oauth_signature] =
          'bYT5CMsGcbgUdFHObYMEfcx6bsw%3D';

      auth['c2'] = '';
      auth['a3'] = '2 q'; // Note: the URI's query parameters also has an "a3"

      const String method = 'POST';
      const String uri =
          'http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b';
      final ClientCredentials clientCredentials =
          ClientCredentials('9djdj82h48djs9d2', 'password');
      const int exampleTimestamp = 137131201;
      const String exampleNonce = '7d8f3e4a';

      //----------------------------------------------------------------

      test('string construction for creating signature', () {
        String signatureBaseString;

        auth.sign(method, uri, clientCredentials, SignatureMethods.hmacSha1,
            timestamp: exampleTimestamp,
            nonce: exampleNonce,
            debugBaseString: (String s) => signatureBaseString = s);

        expect(signatureBaseString, equals(expectedSBS));

        // This test currently fails because the AuthorizationHeader does not
        // handle multiple parameters with the same name. It incorrectly assumes
        // that there is at most one parameter with the same name (that is the
        // case for the oauth_* parameters, but not necessarily the case for other
        // parameters.
      });

      //----------------------------------------------------------------

      test('string construction for signature validation', () {
        String signatureBaseString;

        // The token_secret is not correct, so signature validation will fail.
        // But this test only cares about whether the calculated signature base
        // string has the expected value.

        auth.validate(method, uri, clientCredentials, 'll399dj47dskfjdk',
            debugBaseString: (String s) => signatureBaseString = s);

        expect(signatureBaseString, equals(expectedSBS));
      });
    });
  });
}
