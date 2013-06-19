/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var userByUsername = callbacks('userByUsername')
    , hashPassword = callbacks('hashPassword');

  return oauth2orize.exchange.password(function(client, username, password, scope, done) {
    // TODO verify that this client is allowed to use the password exchange

    // Get the user from the username
    userByUsername(username, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false);

      // Hash the password and check that it's valid
      hashPassword(password, user, function(err, hash) {
        if (err) return done(err);
        // Allow a boolean to be passed
        if (hash === true) return done(null, user);
        // TODO check that the passwords match in a secure way so we can avoid timing attacks and such
        if (user.passhash !== hash) return done(null, false);

        return done(null, user);
      });
    });
  });
}
