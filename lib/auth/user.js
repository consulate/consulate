/**
 * Module dependencies.
 */

var debug = require('simple-debug')('consulate:auth:user');
var LocalStrategy = require('passport-local').Strategy;

/**
 * LocalStrategy
 *
 * This strategy is used to authenticate users based on a username and password.
 * Anytime a request is made to authorize an application, we must ensure that
 * a user is logged in before asking them to approve the request.
 */

module.exports = function(passport, callbacks) {
  var getUser = callbacks('getUser');
  var getUserByUsername = callbacks('getUserByUsername');
  var verifyPassword = callbacks('verifyPassword');

  passport.serializeUser(function(req, user, done) {
    debug('serializing user', user);
    done(null, user.id);
  });

  passport.deserializeUser(function(req, id, done) {
    debug('deserializing user_id', id);
    getUser(req, id, function(err, user) {
      debug('deserialized user_id', id, user);
      if (err) return done(err);
      return done(null, user);
    });
  });

  passport.use(new LocalStrategy({passReqToCallback: true}, function(req, username, password, done) {
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

        return done(null, user);
      });
    });
  }));

  return 'local';
}