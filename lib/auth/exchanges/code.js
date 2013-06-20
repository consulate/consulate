/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var authorizationCode = callbacks('authorizationCode')
    , saveAccessToken = callbacks('saveAccessToken')
    , issueToken = callbacks('issueToken');

  return oauth2orize.exchange.code(function(client, code, redirectURI, done) {
    // Get auth code info from the code
    authorizationCode(code, function(err, authCode) {
      if (err) return done(err);
      if (!authCode) return done(null, false);
      if (client.id !== authCode.client_id) return done(null, false);
      if (redirectURI !== authCode.redirect_uri) return done(null, false);

      // Create a token for the given client and user
      // TODO do we need to pass the user object or just the id?
      issueToken(client, {id: authCode.user_id}, authCode.scope, function(err, token) {
        if (err) return done(err);

        // Save the access token
        saveAccessToken(token, authCode.user_id, authCode.client_id, function(err) {
          if (err) return done(err);
          return done(null, token);
        });
      });
    });
  });
}
