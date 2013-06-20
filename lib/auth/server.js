/**
 * Module dependencies.
 */

var debug = require('debug')('consulate:auth:server')
  , oauth2orize = require('oauth2orize');

exports = module.exports = function(callbacks) {
  var server = oauth2orize()
    , getClient = callbacks('client');

  // Serialize the client
  server.serializeClient(function(client, done) {
    debug('serializing client', client);
    done(null, client.id);
  });

  // Deserialize the client
  server.deserializeClient(function(id, done) {
    debug('deserializing client_id '+id);
    getClient(id, function(err, client) {
      debug('deserialized client_id '+id, client);
      if (err) return done(err);
      return done(null, client);
    });
  });

  // Setup authorize
  server.authorizeClient = function() {
    return server.authorization(function(clientID, redirectURI, scope, type, done) {
      debug('getting client '+clientID+' with redirect_uri '+redirectURI);
      getClient(clientID, function(err, client) {
        debug('got client '+clientID, client);
        if (err) return done(err);
        if (!client) return done(null, false);
        if (!client.redirect_uri) return done(null, false);

        // Check that the redirect_uri is valid
        // TODO maybe implement a fuzzier match i.e. a subpath
        var isValid = Array.isArray(client.redirect_uri)
          ? ~client.redirect_uri.indexOf(redirectURI)
          : client.redirect_uri === redirectURI;
        if (!isValid) return done(null, isValid);

        return done(null, client, redirectURI)
      });
    });
  };

  // Setup the authorize endpoint locals
  server.authorizeLocals = function() {
    return function(req, res, next) {
      var locals = {
        action: '/authorize/decision', // TODO resolve this so we can be mounted anywhere
        transaction: req.oauth2.transactionID,
        user: req.user,
        oauthClient: req.oauth2.client,
        scopes: req.oauth2.client.scopes, // TODO display the ad-hoc scope requests, if any
        optionalScopes: req.oauth2.client.optional_scopes // TODO display the ad-hoc optional scope requests, if any
      };
      debug('setting authorize view locals', locals);
      res.locals(locals);
      next();
    };
  };

  return server;
}
