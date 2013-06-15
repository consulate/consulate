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
        if (!client.return_uri) return done(null, new Error(clientID+' has no registered return_uris'));

        // Check that the return_uri is valid
        // TODO maybe implement a fuzzier match i.e. a subpath
        var isValid = Array.isArray(client.return_uri)
          ? ~client.return_uri.indexOf(redirectURI)
          : client.return_uri === redirectURI;
        if (!isValid) return done(null, isValid);

        client.id = clientID;

        return done(null, client, redirectURI)
      });
    });
  };

  // Setup the authorize endpoint locals
  server.authorizeLocals = function() {
    return function(req, res, next) {
      // TODO expose the scopes and optional_scopes
      res.locals({
        transactionID: req.oauth2.transactionID,
        user: req.user,
        client: req.oauth2.client,
        scopes: req.oauth2.client.scopes, // TODO display the ad-hoc scope requests, if any
        optionalScopes: req.oauth2.client.optional_scopes // TODO display the ad-hoc optional scope requests, if any
      });
      next();
    };
  };

  return server;
}
