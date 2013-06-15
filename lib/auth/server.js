
var oauth2orize = require('oauth2orize');

exports = module.exports = function(callbacks) {
  var server = oauth2orize()
    , getClient = callbacks('client');

  // Setup authorize
  server.authorize = function() {
    return server.authorization(function(clientID, redirectURI, done) {
      getClient(clientID, function(err, client) {
        if (err) return done(err);
        if (!client) return done(null, false);

        // TODO verify redirectURL with the client - THIS IS IMPORTANT

        return done(null, client, redirectURL)
      });
    });
  };

  return server;
}
