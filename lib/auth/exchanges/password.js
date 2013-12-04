/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:password');
var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var getUserByUsername = callbacks('getUserByUsername');
  var verifyPassword = callbacks('verifyPassword');
  var issueTokens = callbacks('issueTokens');

  return oauth2orize.exchange.password(function(req, client, username, password, scope, done) {
    // TODO verify that this client is allowed to use the password exchange

    // Get the user from the username
    debug('getting user by username', username);
    getUserByUsername(req, username, function(err, user) {
      debug('got user by username', username, user);
      if (err) return done(err);
      if (!user) return done(null, false);

      // Hash the password and check that it's valid
      debug('verifying user password');
      verifyPassword(req, user, password, function(err, isValid) {
        debug('verified user password', isValid);
        if (err) return done(err);
        if (!isValid) return done(null, false);

        issueTokens(req, 'password', client, user, scope, done);
      });
    });
  });
}
