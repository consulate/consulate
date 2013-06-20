/**
 * Module dependencies.
 */

var passport = require('passport')
  , LocalStrategy = require('passport-local').Strategy;

/**
 * LocalStrategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */

module.exports = function(callbacks) {
  var getUser = callbacks('user')
    , userByUsername = callbacks('userByUsername')
    , verifyPassword = callbacks('verifyPassword');

  passport.serializeUser(function(user, done) {
    done(null, user.id);
  });

  passport.deserializeUser(function(id, done) {
    getUser(id, function(err, user) {
      if (err) return done(err);
      return done(null, user);
    });
  });

  passport.use(new LocalStrategy(function(username, password, done) {
    // Get the user from the username
    userByUsername(username, function(err, user) {
      if (err) return done(err);
      if (!user) return done(null, false);

      // Hash the password and check that it's valid
      verifyPassword(user, password, function(err, isValid) {
        if (err) return done(err);
        if (!isValid) return done(null, false);

        return done(null, user);
      });
    });
  }));

  return 'local';
}