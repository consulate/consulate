/**
 * Module dependencies
 */

var debug = require('debug')('consulate:auth:exchanges:code')
  , oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var authorizationCode = callbacks('authorizationCode')
    , getUser = callbacks('user')
    , issueToken = callbacks('issueToken')
    , invalidateAuthorizationCode = callbacks('invalidateAuthorizationCode');

  return oauth2orize.exchange.code(function(client, code, redirectURI, done) {
    // Get auth code info from the code
    debug('getting authorization code '+code);
    authorizationCode(code, function(err, authCode) {
      debug('got authorization code '+code, authCode);
      if (err) return done(err);
      if (!authCode) return done(null, false);
      if (!client) return done(null, false);
      if (client.id !== authCode.client_id) return done(null, false);
      if (redirectURI !== authCode.redirect_uri) return done(null, false);

      // Find the user from the code
      debug('getting user '+authCode.user_id);
      getUser(authCode.user_id, function(err, user) {
        debug('got user '+authCode.user_id, user);
        if (err) return done(err);
        if (!user) return done(null, false);

        // Complete the exchange of the valid code for an access token
        debug('issuing token for user '+authCode.user_id);
        issueToken(client, user, authCode.scope, function(err, token) {
          debug('issued token for user '+authCode.user_id, token);
          if (err) return done(err);
          if (!token) return done(null, false);

          // Invalidate the authorization code now that we've used it
          debug('invalidating authorization code '+code);
          invalidateAuthorizationCode(code, function(err) {
            debug('invalidated authorization code '+code);
            if (err) return done(err);
            done(null, token);
          });
        });
      });
    });
  });
}
