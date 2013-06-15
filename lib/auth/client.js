
var passport = require('passport')
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

exports = module.exports = function(getClient) {

  function callback(clientID, clientSecret, done) {
    getClient(clientID, function(err, client) {
      if (err) return done(err);
      if (!client) return done(null, false);
      // TODO we should probably do a secure compare here to avoid timing attacks
      if (client.secret !== clientSecret) return done(null, false);
      return done(null, client);
    });
  };

  passport.use(new BasicStrategy(callback));
  passport.use(new ClientPasswordStrategy(callback));
  return exports;
}

exports.verifyApp = function() {
  return passport.authenticate(['basic', 'oauth2-client-password'], { session: false });
};
