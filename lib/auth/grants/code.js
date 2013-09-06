/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:grants:code')
  , oauth2orize = require('oauth2orize')
  , clientScopesNoop = require('../../utils').clientScopesNoop
  , defaultClientScopes = require('../../utils').defaultClientScopes
  , defaultFilterScopesByClient = require('../../utils').defaultFilterScopesByClient
  , defaultFilterScopesByUser = require('../../utils').defaultFilterScopesByUser;

module.exports = function(callbacks) {
  var createAuthorizationCode = callbacks('createAuthorizationCode')
    , clientScopes = callbacks('clientScopes', defaultClientScopes)
    , filterScopesByClient = callbacks('filterScopesByClient', defaultFilterScopesByClient)
    , filterScopesByUser = callbacks('filterScopesByUser', defaultFilterScopesByUser);

  return oauth2orize.grant.code(function(req, client, redirectURI, user, ares, done) {

    var defaultScopes = ares.scope
      ? clientScopesNoop(ares.scope)
      : clientScopes;

    defaultScopes(req, client, function(err, scopes) {

      debug('filtering scopes by client', client, scopes);
      filterScopesByClient(req, client, scopes, function(err, clientScope) {
        debug('filtered scopes by client', client, clientScope);
        if (err) return done(err);
        if (!clientScope) return done(null, false);

        debug('filtering scopes by user', user, clientScope);
        filterScopesByUser(req, user, clientScope, function(err, userScopes) {
          debug('filtered scopes by user', user, userScopes);
          if (err) return done(err);
          if (!userScopes) return done(null, userScopes);

          ares.scope = userScopes;

          debug('creating auth code for client', client, 'and user', user);
          return createAuthorizationCode(req, client, redirectURI, user, ares, function(err, code) {
            debug('created auth code', code);
            done(err, code);
          });
        });
      });
    });
  });
}
