/**
 * Module dependencies
 */
var passport = require('passport')
  , FacebookStrategy = require('passport-facebook').Strategy
  , env = require('envs')
  , db = require('./db');

passport.use(new FacebookStrategy({
  clientID: env('FACEBOOK_CLIENT_ID'),
  clientSecret: env('FACEBOOK_CLIENT_SECRET'),
  callbackURL: env('FACEBOOK_CALLBACK_URL', 'http://localhost:5002/auth/facebook')
}, function(accessToken, refreshToken, profile, done) {
  profile.accessToken = accessToken;
  profile.refreshToken = refreshToken;
  done(null, profile);
}))

module.exports = function() {
  return function(req, res, next) {
    // We want to do some custom handling here
    passport.authenticate('facebook', function(err, facebookUser, info) {
      if (err) return next(err);

      // We couldn't find the user or the password was invalid
      if (!facebookUser) {
        res.locals({loginInfo: info || 'Invalid username/password'});
        return res.render('login');
      }

      db.getUserByFacebookOrCreate(facebookUser, function(err, user) {
        if (err) return next(err);

        req.logIn(user, function(err) {
          if (err) return next(err);

          var returnTo = '/authorize';

          // Redirect to where we came from
          return res.redirect(returnTo);
        });
      });
    })(req, res, next);
  };
};
