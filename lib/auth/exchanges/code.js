/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:code');
var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var getAuthorizationCode = callbacks('getAuthorizationCode');
  var getUser = callbacks('getUser');
  var issueTokens = callbacks('issueTokens');
  var invalidateAuthorizationCode = callbacks('invalidateAuthorizationCode');

  return oauth2orize.exchange.code(function(req, client, code, redirectURI, done) {
    // Get auth code info from the code
    debug('getting authorization code', code);
    getAuthorizationCode(req, code, function(err, authCode) {
      debug('got authorization code', code, authCode);
      if (err) return done(err);
      if (!authCode) return done(null, false);
      if (!client) return done(null, false);
      if (client.id !== authCode.client_id) return done(null, false);
      if (redirectURI !== authCode.redirect_uri) return done(null, false);

      // Find the user from the code
      debug('getting user', authCode.user_id);
      getUser(req, authCode.user_id, function(err, user) {
        debug('got user', authCode.user_id, user);
        if (err) return done(err);
        if (!user) return done(null, false);

        issueTokens(req, 'code', client, user, authCode.scope, function(err, accessToken, refreshToken, params) {
          if (err) return done(err);
          if (!accessToken) return done(null, false);

          // Invalidate the authorization code now that we've used it
          debug('invalidating authorization code', code);
          invalidateAuthorizationCode(req, code, function(err) {
            debug('invalidated authorization code', code);
            if (err) return done(err);
            done(null, accessToken, refreshToken, params);
          });
        });
      });
    });
  });
}
