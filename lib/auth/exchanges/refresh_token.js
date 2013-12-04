/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:refresh_token');
var oauth2orize = require('oauth2orize');
var merge = require('../../utils').merge;

module.exports = function(callbacks) {
  var getRefreshToken = callbacks('getRefreshToken');
  var getUser = callbacks('getUser');
  var issueToken = callbacks('issueToken');
  var createRefreshToken = callbacks('createRefreshToken');
  var invalidateRefreshToken = callbacks('invalidateRefreshToken');
  var getAdditionalParams = callbacks('getAdditionalParams', function(req, type, client, user, scope, done) { done(); });

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
        debug('issuing token for user', info.user_id);
        scope = scope || info.scope;
        issueToken(req, client, user, scope, function(err, token, params) {
          debug('issued token for user', info.user_id, token);
          if (err) return done(err);
          if (!token) return done(null, false);

          params = params || {};

          debug('creating refresh token for user', info.user_id);
          createRefreshToken(req, client, user, scope, function(err, rt, refreshTokenParams) {
            debug('created refresh token for user', info.user_id, rt);
            if (err) return done(err);

            merge(params, refreshTokenParams);

            getAdditionalParams(req, 'refresh_token', client, null, scope, function(err, additionalParams) {
              if (err) return done(err);

              merge(params, additionalParams);

              debug('invalidating refresh token for user', info.user_id, refreshToken);
              invalidateRefreshToken(req, refreshToken, function(err) {
                debug('invalidated refresh token for user', info.user_id, refreshToken);
                if (err) return done(err);

                done(null, token, rt, params);
              });
            });
          });
        });
      });
    });
  });
}
