/**
 * Module dependencies.
 */

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

exports = module.exports = function(callbacks) {
  var getClient = callbacks('client');

  function verifyClientCredentials(clientID, clientSecret, done) {
    getClient(clientID, function(err, client) {
      if (err) return done(err);
      if (!client) return done(null, false);
      // TODO we should probably do a secure compare here to avoid timing attacks
      if (client.secret !== clientSecret) return done(null, false);
      return done(null, client);
    });
  };

  function verifyPublicClient(clientID, done) {
    getClient(clientID, function(err, client) {
      if (err) return done(err);
      if (!client) return done(null, false);
      // Client was issued credentials, and must authenticate with them
      if (client.secret) return done(null, false);
      return done(null, client);
    });
  };

  passport.use(new BasicStrategy(verifyClientCredentials));
  passport.use(new ClientPasswordStrategy(verifyClientCredentials));
  passport.use(new PublicClientStrategy(verifyPublicClient));
  return exports;
}

exports.verifyApp = function() {
  return function verifyApp(req, res, next) {
    var authenticate = passport.authenticate(['basic', 'oauth2-client-password'], { session: false });
    authenticate(req, res, function(err) {
      if (err) return next(err);
      if (req.user) return next();
      // Only allow public clients on authorization_code exchanges
      if (req.body['grant_type'] === 'authorization_code') {
        var identify = passport.authenticate('oauth2-public-client', { session: false });
        return identify(req, res, next);
      }
    });
  }
};
