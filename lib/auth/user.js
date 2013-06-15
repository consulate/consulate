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

exports = module.exports = function(callbacks) {
  var getUser = callbacks('user')
    , userByUsername = callbacks('userByUsername')
    , hashPassword = callbacks('hashPassword');

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
      hashPassword(password, user, function(err, hash) {
        if (err) return done(err);
        // TODO check that the passwords match in a secure way so we can avoid timing attacks and such
        if (user.passhash !== hash) return done(null, false);

        return done(null, user);
      });
    });
  }));

  return exports;
}

exports.handleLogin = function() {
  return function(req, res, next) {
    // We want to do some custom handling here
    passport.authenticate('local', function(err, user, info) {
      if (err) return next(err);

      // We couldn't find the user or the password was invalid
      if (!user) {
        res.locals({loginInfo: info || 'Invalid username/password'});
        return next();
      }

      req.logIn(user, function(err) {
        if (err) return next(err);
        // TODO resolve this path so it can be mounted anywhere
        return res.redirect("/authorize");
      });
    })(req, res, next);
  };
};
