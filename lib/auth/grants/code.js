/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize')
  , uid = require('websafe-uid').uid;

module.exports = function(callbacks) {
  var saveAuthorizationCode = callbacks('saveAuthorizationCode');

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    // TODO is this a good length? Should we let the app create its own?
    var code = uid(128);

    // Get auth code info from the code
    // TODO we should save the requested scope as well
    saveAuthorizationCode(code, user.id, client.id, redirectURI, function(err) {
      if (err) return done(err);
      done(null, code);
    });
  });
}