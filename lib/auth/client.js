/**
 * Module dependencies.
 */

var debug = require('simple-debug')('consulate:auth:client');
var BasicStrategy = require('passport-http').BasicStrategy;
var ClientPasswordStrategy = require('passport-oauth2-client-password').Strategy;
var PublicClientStrategy = require('passport-oauth2-public-client').Strategy;
var AuthorizationError = require('oauth2orize/lib/errors/authorizationerror');

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

exports = module.exports = function(passport, callbacks) {
  var getClient = callbacks('getClient');

  function verifyClientCredentials(req, clientID, clientSecret, done) {
    debug('getting client', clientID);
    getClient(req, clientID, function(err, client) {
      debug('got client', clientID, client);
      if (err) return done(err);
      if (!client) return done(null, false);
      // TODO we should probably do a secure compare here to avoid timing attacks
      if (client.secret !== clientSecret) return done(null, false);
      return done(null, client);
    });
  };

  function verifyPublicClient(req, clientID, done) {
    debug('getting client', clientID);
    getClient(req, clientID, function(err, client) {
      debug('got client', clientID, client)
      if (err) return done(err);
      if (!client) return done(null, false);
      // Client was issued credentials, and must authenticate with them
      if (client.secret) return done(null, false);
      return done(null, client);
    });
  };

  var options = {
    passReqToCallback: true
  };

  passport.use(new BasicStrategy(options, verifyClientCredentials));
  passport.use(new ClientPasswordStrategy(options, verifyClientCredentials));
  passport.use(new PublicClientStrategy(options, verifyPublicClient));

  return verifyApp(passport);
}

function verifyApp(passport) {
  return function(options) {
    options = options || { public_exchanges: ['authorization_code'] };

    return function verifyApp(req, res, next) {
      passport.authenticate(['basic', 'oauth2-client-password'], { session: false }, function(err, user, info) {
        if (err) return next(err);
        if (user) return req.logIn(user, next);

        // Only allow public clients on specific exchanges
        if (!~options.public_exchanges.indexOf(req.body['grant_type'])) return next(new AuthorizationError('Unauthorized client', 'invalid_client'));

        return passport.authenticate('oauth2-public-client', {
          session: false
        })(req, res, next);
      })(req, res, next);
    }
  };
};
