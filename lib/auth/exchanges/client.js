/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:client')
  , oauth2orize = require('oauth2orize')
  , clientScopesNoop = require('../../utils').clientScopesNoop
  , defaultClientScopes = require('../../utils').defaultClientScopes
  , defaultFilterScopesByClient = require('../../utils').defaultFilterScopesByClient;

module.exports = function(callbacks) {
  var clientScopes = callbacks('clientScopes', defaultClientScopes)
    , filterScopesByClient = callbacks('filterScopesByClient', defaultFilterScopesByClient)
    , issueToken = callbacks('issueToken');

  return oauth2orize.exchange.clientCredentials(function(req, client, scope, done) {
    var defaultScopes = scope
      ? clientScopesNoop(scope)
      : clientScopes;

    defaultScopes(req, client, function(err, scopes) {
      debug('filtering scopes by client', client, scopes);
      filterScopesByClient(req, client, scopes, function(err, clientScope) {
        debug('filtered scopes by client', client, clientScope);
        if (err) return done(err);
        if (!clientScope) return done(null, false);

        debug('issuing token for client', client);
        return issueToken(req, client, null, clientScope, function(err, accessToken, refreshToken, params) {
          debug('issued token for client', client, accessToken);

          params = params || {};

          // If the issued access token scope
          // is different from the one requested by the client, the authorization
          // server MUST include the "scope" response parameter to inform the
          // client of the actual scope granted.
          if (!scope || scope.length !== clientScope.length) params.scope = clientScope.join(' ');

          done(err, accessToken, refreshToken, params);
        });
      });
    });
  });
}
