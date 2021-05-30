import 'dart:async';

/// An Exception that should be thrown when overriding `refreshToken` if the
/// refresh fails and should result in a force-logout.
class RevokeTokenException implements Exception {}

/// {@template oauth2_token}
/// Standard OAuth2Token as defined by
/// https://www.oauth.com/oauth2-servers/access-tokens/access-token-response/
/// {@endtemplate}
class OAuth2Token {
  /// {macro oauth2_token}
  const OAuth2Token({
    required this.accessToken,
    this.tokenType = 'bearer',
    this.expiresIn,
    this.refreshToken,
    this.scope,
  });

  /// The access token string as issued by the authorization server.
  final String accessToken;

  /// The type of token this is, typically just the string “bearer”.
  final String? tokenType;

  /// If the access token expires, the server should reply
  /// with the duration of time the access token is granted for.
  final int? expiresIn;

  /// Token which applications can use to obtain another access token.
  final String? refreshToken;

  /// Application scope granted as defined in https://oauth.net/2/scope
  final String? scope;
}

/// Enum representing the current authentication status of the application.
abstract class AuthenticationState<T> {
  /// The status before the true [AuthenticationState] has been determined.
  factory AuthenticationState.initial() => Initial<T>();

  /// The status when the application is authenticated.
  factory AuthenticationState.authenticated(T token) => Authenticated<T>(token);

  /// The status when the application is not authenticated.
  factory AuthenticationState.unAuthenticated() => UnAuthenticated<T>();
}

/// The status before the true [AuthenticationState] has been determined.
class Initial<T> implements AuthenticationState<T> {}

/// The status when the application is authenticated.
class Authenticated<T> implements AuthenticationState<T> {
  /// token is provided when state is authenticated
  Authenticated(this.token);

  /// current token for stream event
  final T token;
}

/// The status when the application is not authenticated.
class UnAuthenticated<T> implements AuthenticationState<T> {}

/// An interface which must be implemented to
/// read, write, and delete the `Token`.
abstract class TokenStorage<T> {
  /// Returns the stored token asynchronously.
  Future<T?> read();

  /// Saves the provided [token] asynchronously.
  Future<void> write(T token);

  /// Deletes the stored token asynchronously.
  Future<void> delete();
}

/// Function responsible for building the token header(s) give a [token].
typedef TokenHeaderBuilder<T> = Map<String, String> Function(
  T token,
);

/// A [TokenStorage] implementation that keeps the token in memory.
class InMemoryTokenStorage<T> implements TokenStorage<T> {
  T? _token;

  @override
  Future<void> delete() async {
    _token = null;
  }

  @override
  Future<T?> read() async {
    return _token;
  }

  @override
  Future<void> write(T token) async {
    _token = token;
  }
}

/// {@template fresh_mixin}
/// A mixin which handles core token refresh functionality.
/// {@endtemplate}
mixin FreshMixin<T> {
  AuthenticationState _authenticationState = AuthenticationState<T>.initial();

  late TokenStorage<T> _tokenStorage;

  T? _token;

  final StreamController<AuthenticationState<T>> _controller =
      StreamController<AuthenticationState<T>>.broadcast()
        ..add(AuthenticationState<T>.initial());

  /// Setter for the [TokenStorage] instance.
  set tokenStorage(TokenStorage<T> tokenStorage) {
    _tokenStorage = tokenStorage..read().then(_updateState);
  }

  /// Returns the current token.
  Future<T?> get token async {
    if (!(_authenticationState is Initial)) return _token;
    await authenticationState.first;
    return _token;
  }

  /// Returns a [Stream<AuthenticationState>] which can be used to get notified
  /// of changes to the authentication state based on the presence/absence of a token.
  Stream<AuthenticationState> get authenticationState async* {
    yield _authenticationState;
    yield* _controller.stream;
  }

  /// Sets the internal [token] to the provided [token]
  /// and updates the [AuthenticationState] accordingly.
  ///
  /// If the provided token is null, the [AuthenticationState] will be updated
  /// to `unauthenticated` and the token will be removed from storage, otherwise
  /// it will be updated to `authenticated`and save to storage.
  Future<void> setToken(T? token) async {
    if (token == null) return clearToken();
    await _tokenStorage.write(token);
    _updateState(token);
  }

  /// Delete the storaged [token]. and emit the
  /// `AuthenticationState.unauthenticated` if authenticationStatus
  /// not is `AuthenticationState.unauthenticated`
  /// This method should be called when the token is no longer valid.
  Future<void> revokeToken() async {
    await _tokenStorage.delete();
    if (!(_authenticationState is UnAuthenticated)) {
      _authenticationState = AuthenticationState<T>.unAuthenticated();
      _controller.add(_authenticationState);
    }
  }

  /// Clears token storage and updates the [AuthenticationState]
  /// to [UnAuthenticated].
  Future<void> clearToken() async {
    await _tokenStorage.delete();
    _updateState(null);
  }

  /// Closes Fresh StreamController.
  ///
  /// [setToken] and [clearToken] must not be called after this method.
  ///
  /// Calling this method more than once is allowed, but does nothing.
  Future<void> close() => _controller.close();

  /// Update the internal [token] and updates the
  /// [AuthenticationState] accordingly.
  ///
  /// If the provided token is null, the [AuthenticationState] will
  /// be updated to `AuthenticationState.unauthenticated` otherwise it
  /// will be updated to `AuthenticationState.authenticated`.
  void _updateState(T? token) {
    _authenticationState = token != null
        ? AuthenticationState<T>.authenticated(token)
        : AuthenticationState<T>.unAuthenticated();
    _token = token;
    _controller.add(_authenticationState);
  }
}
