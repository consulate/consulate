/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var authorizationCode = callbacks('authorizationCode')
    , getUser = callbacks('user')
    , issueToken = callbacks('issueToken');

  return oauth2orize.exchange.code(function(client, code, redirectURI, done) {
    // Get auth code info from the code
    authorizationCode(code, function(err, authCode) {
      if (err) return done(err);
      if (!authCode) return done(null, false);
      if (!client) return done(null, false);
      if (client.id !== authCode.client_id) return done(null, false);
      if (redirectURI !== authCode.redirect_uri) return done(null, false);

      // Find the user from the code
      getUser(authCode.user_id, function(err, user) {
        if (err) return done(err);
        if (!user) return done(null, false);

        // Complete the exchange of the valid code for an access token
        issueToken(client, user, authCode.scope, done);
      });
    });
  });
}
