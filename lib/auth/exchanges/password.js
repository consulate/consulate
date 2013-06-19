/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var userByUsername = callbacks('userByUsername')
    , verifyPassword = callbacks('verifyPassword')
    , issueToken = callbacks('issueToken');

  return oauth2orize.exchange.password(function(client, username, password, scope, done) {
    // TODO verify that this client is allowed to use the password exchange

    // Get the user from the username
    userByUsername(username, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false);

      // Hash the password and check that it's valid
      verifyPassword(user, password, function(err, isValid) {
        if (err) return done(err);
        if (!isValid) return done(null, false);

        return issueToken(client, user, scope, done);
      });
    });
  });
}
