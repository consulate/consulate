/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var saveAuthorizationCode = callbacks('saveAuthorizationCode');

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    // TODO create a auth code
    var code = 'authCode123';

    // Get auth code info from the code
    saveAuthorizationCode(code, user.id, client.id, redirectURI, function(err) {
      if (err) return done(err);
      done(null, code);
    });
  });
}