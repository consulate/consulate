/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:code');
var oauth2orize = require('oauth2orize');
var merge = require('../../utils').merge;

module.exports = function(callbacks) {
  var getAuthorizationCode = callbacks('getAuthorizationCode');
  var getUser = callbacks('getUser');
  var issueToken = callbacks('issueToken');
  var invalidateAuthorizationCode = callbacks('invalidateAuthorizationCode');
  var createRefreshToken = callbacks('createRefreshToken', function(req, client, user, scope, done) { done(); });
  var getAdditionalParams = callbacks('getAdditionalParams', function(req, type, client, user, scope, done) { done(); });

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

        // Complete the exchange of the valid code for an access token
        debug('issuing token for user', authCode.user_id);
        issueToken(req, client, user, authCode.scope, function(err, token, params) {
          debug('issued token for user', authCode.user_id, token);
          if (err) return done(err);
          if (!token) return done(null, false);

          params = params || {};

          debug('creating refresh token for user', authCode.user_id);
          createRefreshToken(req, client, user, authCode.scope, function(err, refreshToken, refreshTokenParams) {
            debug('created refresh token for user', authCode.user_id, refreshToken);
            if (err) return done(err);

            // Merge the refresh token params
            merge(params, refreshTokenParams);

            getAdditionalParams(req, 'code', client, user, authCode.scope, function(err, additionalParams) {
              if (err) return done(err);

              // Merge any additional params
              merge(params, additionalParams);

              // Invalidate the authorization code now that we've used it
              debug('invalidating authorization code', code);
              invalidateAuthorizationCode(req, code, function(err) {
                debug('invalidated authorization code', code);
                if (err) return done(err);
                done(null, token, refreshToken, params);
              });
            });
          });
        });
      });
    });
  });
}
