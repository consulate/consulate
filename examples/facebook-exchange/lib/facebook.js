/**
 * Module dependencies
 */
var passport = require('passport')
  , FacebookStrategy = require('passport-facebook').Strategy;

/**
 * Facebook Exchange Plugin
 */

exports = module.exports = function(options) {
  var path = options.path || '/auth/facebook'
    , getUserByFacebookOrCreate = options.getUserByFacebookOrCreate;

  return function(app) {

    passport.use(new FacebookStrategy({
      clientID: options.clientID,
      clientSecret: options.clientSecret,
      callbackURL: options.callbackURL
    }, function(accessToken, refreshToken, profile, done) {
      profile.accessToken = accessToken;
      profile.refreshToken = refreshToken;
      done(null, profile);
    }));

    app.use(path, exports.login(getUserByFacebookOrCreate));
  };
};

exports.login = function(getUserByFacebookOrCreate) {
  return function(req, res, next) {
    // We want to do some custom handling here
    passport.authenticate('facebook', function(err, facebookUser, info) {
      if (err) return next(err);

      // The user didn't end up logging in through facebook
      if (!facebookUser) return res.redirect('/login');

      getUserByFacebookOrCreate(facebookUser, function(err, user) {
        if (err) return next(err);

        req.logIn(user, function(err) {
          if (err) return next(err);

          var returnTo = req.session.returnTo;
          // Delete it
          delete req.session.returnTo;

          // Redirect to where we came from
          return res.redirect(returnTo);
        });
      });
    })(req, res, next);
  };
};
