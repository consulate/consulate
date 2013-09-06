/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:password')
  , oauth2orize = require('oauth2orize')
  , clientScopesNoop = require('../../utils').clientScopesNoop
  , defaultClientScopes = require('../../utils').defaultClientScopes
  , defaultFilterScopesByClient = require('../../utils').defaultFilterScopesByClient
  , defaultFilterScopesByUser = require('../../utils').defaultFilterScopesByUser;

module.exports = function(callbacks) {
  var userByUsername = callbacks('userByUsername')
    , verifyPassword = callbacks('verifyPassword')
    , issueToken = callbacks('issueToken')
    , clientScopes = callbacks('clientScopes', defaultClientScopes)
    , filterScopesByClient = callbacks('filterScopesByClient', defaultFilterScopesByClient)
    , filterScopesByUser = callbacks('filterScopesByUser', defaultFilterScopesByUser);

  return oauth2orize.exchange.password(function(req, client, username, password, scope, done) {
    // TODO verify that this client is allowed to use the password exchange

    var defaultScopes = scope
      ? clientScopesNoop(scope)
      : clientScopes;

    defaultScopes(req, client, function(err, scopes) {

      debug('filtering scopes by client', client, scopes);
      filterScopesByClient(req, client, scopes, function(err, clientScope) {
        debug('filtered scopes by client', client, clientScope);
        if (err) return done(err);
        if (!clientScope) return done(null, false);

        // Get the user from the username
        debug('getting user by username', username);
        userByUsername(req, username, function(err, user) {
          debug('got user by username', username, user);
          if (err) return done(err);
          if (!user) return done(null, false);

          // Hash the password and check that it's valid
          debug('verifying user password');
          verifyPassword(req, user, password, function(err, isValid) {
            debug('verified user password', isValid);
            if (err) return done(err);
            if (!isValid) return done(null, false);

            debug('filtering scopes by user', user, clientScope);
            filterScopesByUser(req, user, clientScope, function(err, userScopes) {
              debug('filtered scopes by user', user, userScopes);
              if (err) return done(err);
              if (!userScopes) return done(null, userScopes);

              debug('issuing token for user ', username);
              return issueToken(req, client, user, userScopes, function(err, accessToken, refreshToken, params) {
                debug('issued token for user ', username, accessToken);

                params = params || {};

                // If the issued access token scope
                // is different from the one requested by the client, the authorization
                // server MUST include the "scope" response parameter to inform the
                // client of the actual scope granted.
                if (!scope || scope.length !== userScopes.length) params.scope = userScopes.join(' ');

                done(err, accessToken, refreshToken, params);
              });
            });
          });
        });
      });
    });
  });
}
