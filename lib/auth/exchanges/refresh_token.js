/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:refresh_token');
var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var getRefreshToken = callbacks('getRefreshToken');
  var getUser = callbacks('getUser');
  var issueTokens = callbacks('issueTokens');
  var invalidateRefreshToken = callbacks('invalidateRefreshToken');

  return oauth2orize.exchange.refreshToken(function(req, client, refreshToken, scope, done) {
    // Get the refresh token information
    getRefreshToken(req, refreshToken, function(err, info) {
      if (err) return done(err);
      if (!info) return done(null, false);
      if (client.id !== info.client_id) return done(null, false);

      // Find the user from the refresh token
      debug('getting user', info.user_id);
      getUser(req, info.user_id, function(err, user) {
        debug('got user', info.user_id, user);
        if (err) return done(err);
        if (!user) return done(null, false);

        // Complete the exchange of the valid refresh token for an access token
        scope = scope || info.scope;
        issueTokens(req, 'refresh_token', client, user, scope, function(err, accessToken, newRefreshToken, params) {
          if (err) return done(err);
          if (!accessToken) return done(null, false);

          debug('invalidating refresh token for user', info.user_id, refreshToken);
          invalidateRefreshToken(req, refreshToken, function(err) {
            debug('invalidated refresh token for user', info.user_id, refreshToken);
            if (err) return done(err);

            done(null, accessToken, newRefreshToken, params);
          });
        });
      });
    });
  });
}
