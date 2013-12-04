/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:password');
var oauth2orize = require('oauth2orize');
var merge = require('../../utils').merge;

module.exports = function(callbacks) {
  var userByUsername = callbacks('userByUsername');
  var verifyPassword = callbacks('verifyPassword');
  var issueToken = callbacks('issueToken');
  var createRefreshToken = callbacks('createRefreshToken', function(req, client, user, scope, done) { done(); });
  var getAdditionalParams = callbacks('additionalParams', function(req, type, client, user, scope, done) { done(); });

  return oauth2orize.exchange.password(function(req, client, username, password, scope, done) {
    // TODO verify that this client is allowed to use the password exchange

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

        // Complete the exchange of the valid code for an access token
        debug('issuing token for user', user.id);
        issueToken(req, client, user, scope, function(err, token, params) {
          debug('issued token for user', user.id, token);
          if (err) return done(err);
          if (!token) return done(null, false);

          params = params || {};

          debug('creating refresh token for user', user.id);
          createRefreshToken(req, client, user, scope, function(err, refreshToken, refreshTokenParams) {
            debug('created refresh token for user', user.id, refreshToken);
            if (err) return done(err);

            // Merge the refresh token params
            merge(params, refreshTokenParams);

            getAdditionalParams(req, 'password', client, user, scope, function(err, additionalParams) {
              if (err) return done(err);

              // Merge any additional params
              merge(params, additionalParams);

              done(null, token, refreshToken, params);
            });
          });
        });
      });
    });
  });
}
