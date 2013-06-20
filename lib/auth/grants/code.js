/**
 * Module dependencies
 */

var oauth2orize = require('oauth2orize')
  , uid = require('websafe-uid').uid;

module.exports = function(callbacks) {
  var saveAuthorizationCode = callbacks('saveAuthorizationCode')
    , createAuthorizationCode = callbacks('createAuthorizationCode', createAuthorizationCodeUID);

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    createAuthorizationCode(function(err, code) {
      if (err) return done(err);

      // Get auth code info from the code
      // TODO we should save the requested scope as well
      saveAuthorizationCode(code, user.id, client.id, redirectURI, function(err) {
        if (err) return done(err);
        done(null, code);
      });
    });
  });
}

function createAuthorizationCodeUID (done) {
  done(null, uid(128));
}
