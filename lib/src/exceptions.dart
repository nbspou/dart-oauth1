library oauth_exceptions;

//################################################################
/// Abstract base class for exceptions thrown by the OAuth library.

abstract class BadOAuth implements Exception {
  const BadOAuth(this.reason);

  /// Reason why the OAuth authorization request is not valid.
  final String reason;

  @override
  String toString() => 'OAuth invalid: $reason';
}

//================================================================
// Exceptions indicating problems with the OAuth protocol parameters.
//
// These can occur when validating an OAuth request, as well as when updating
// or retrieving OAuth protocol parameters.

//----------------------------------------------------------------
/// An OAuth protocol parameter incorrectly has multiple values.

class MultiValueParameter extends BadOAuth {
  const MultiValueParameter(this.name) : super('parameter has multiple values');

  /// Name of the parameter with multiple values.
  final String name;

  @override
  String toString() => '$reason: $name';
}

//----------------------------------------------------------------
/// An OAuth protocol parameter has the wrong value.

class BadParameterValue extends BadOAuth {
  const BadParameterValue(String reason, this.name, this.value) : super(reason);

  /// Name of the parameter with a bad value.
  final String name;

  /// The bad value.
  final String value;

  @override
  String toString() => '$reason: $name=$value';
}

//================================================================
// Exceptions thrown when validating an OAuth request.

//----------------------------------------------------------------
/// An OAuth protocol parameter is required but is missing.

class MissingParameter extends BadOAuth {
  const MissingParameter(this.name) : super('required parameter is missing');

  /// Name of the missing parameter.
  final String name;

  @override
  String toString() => '$reason: $name';
}

//----------------------------------------------------------------
/// The signature is not valid.

class SignatureInvalid extends BadOAuth {
  SignatureInvalid(this.signatureBaseString) : super('signature invalid');

  /// The _signature base string_ used for validating the signature.
  ///
  /// Most programs should ignore this member. This value is only useful for
  /// debugging the internal implementation of OAuth.

  final String signatureBaseString;
}
