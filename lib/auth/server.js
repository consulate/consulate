/**
 * Module dependencies.
 */

var oauth2orize = require('oauth2orize');

exports = module.exports = function(callbacks) {
  var server = oauth2orize()
    , getClient = callbacks('client');

  // Serialize the client
  server.serializeClient(function(client, done) {
    done(null, client.id);
  });

  // Deserialize the client
  server.deserializeClient(function(id, done) {
    getClient(id, function(err, client) {
      if (err) return done(err);
      return done(null, client);
    });
  });

  // Setup authorize
  server.authorizeClient = function() {
    return server.authorization(function(clientID, redirectURI, scope, type, done) {
      getClient(clientID, function(err, client) {
        if (err) return done(err);
        if (!client) return done(null, false);
        if (!client.redirect_uri) return done(null, false);

        // Check that the redirect_uri is valid
        // TODO maybe implement a fuzzier match i.e. a subpath
        var isValid = Array.isArray(client.redirect_uri)
          ? ~client.redirect_uri.indexOf(redirectURI)
          : client.redirect_uri === redirectURI;
        if (!isValid) return done(null, isValid);

        client.id = clientID;

        return done(null, client, redirectURI)
      });
    });
  };

  // Setup the authorize endpoint locals
  server.authorizeLocals = function() {
    return function(req, res, next) {
      res.locals({
        action: '/authorize/decision', // TODO resolve this so we can be mounted anywhere
        transaction: req.oauth2.transactionID,
        user: req.user,
        oauthClient: req.oauth2.client,
        scopes: req.oauth2.client.scopes, // TODO display the ad-hoc scope requests, if any
        optionalScopes: req.oauth2.client.optional_scopes // TODO display the ad-hoc optional scope requests, if any
      });
      next();
    };
  };

  return server;
}
