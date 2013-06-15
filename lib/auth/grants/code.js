/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var saveAuthorizationCode = callbacks('saveAuthorizationCode');

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    // TODO create a auth code
    var code = '123';

    // Get auth code info from the code
    saveAuthorizationCode(code, client.id, redirectURI, user.id, function(err) {
      if (err) return done(err);
      done(null, code);
    });
  });
}
