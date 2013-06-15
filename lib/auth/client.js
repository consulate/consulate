
var login = require('connect-ensure-login')
  , passport = require('passport')
  , BasicStrategy = require('passport-http').BasicStrategy
  , ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;

/**
 * BasicStrategy & ClientPasswordStrategy
 *
 * These strategies are used to authenticate registered OAuth clients.  They are
 * employed to protect the `token` endpoint, which consumers use to obtain
 * access tokens.  The OAuth 2.0 specification suggests that clients use the
 * HTTP Basic scheme to authenticate.  Use of the client password strategy
 * allows clients to send the same credentials in the request body (as opposed
 * to the `Authorization` header).  While this approach is not recommended by
 * the specification, in practice it is quite common.
 */

exports = module.exports = function(callback) {
  passport.use(new BasicStrategy(callback));
  passport.use(new ClientPasswordStrategy(callback));
  return exports;
}

exports.verifyApp = function() {
  return passport.authenticate(['basic', 'oauth2-client-password'], { session: false });
};

