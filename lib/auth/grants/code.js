/**
 * Module dependencies
 */

var debug = require('debug')('consulate:auth:grants:code')
  , oauth2orize = require('oauth2orize')
  , uid = require('websafe-uid').uid;

module.exports = function(callbacks) {
  var saveAuthorizationCode = callbacks('saveAuthorizationCode')
    , createAuthorizationCode = callbacks('createAuthorizationCode', createAuthorizationCodeUID);

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    debug('creating auth code for client', client);
    createAuthorizationCode(function(err, code) {
      debug('created auth code '+code);
      if (err) return done(err);

      // Get auth code info from the code
      // TODO we should save the requested scope as well
      debug('saving auth code '+code);
      saveAuthorizationCode(code, user.id, client.id, redirectURI, function(err) {
        debug('saved auth code '+code, err);
        if (err) return done(err);
        done(null, code);
      });
    });
  });
}

function createAuthorizationCodeUID (done) {
  done(null, uid(128));
}
