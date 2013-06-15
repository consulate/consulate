/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(server, callbacks) {
  var userByUsername = callbacks('userByUsername')
    , hashPassword = callbacks('hashPassword');

  return server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
    // Get the user from the username
    userByUsername(username, function(err, user) {
      if (err) return done(err);

      // Hash the password and check that it's valid
      hashPassword(password, user, function(err, hash) {
        if (err) return done(err);
        // TODO check that the passwords match in a secure way so we can avoid timing attacks and such
        return done(null, user.passhash === hash);
      });
    });
  }));
}
