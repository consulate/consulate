/**
 * Module dependencies
 */

var debug = require('debug')('consulate:auth:grants:code')
  , oauth2orize = require('oauth2orize')
  , uid = require('websafe-uid').uid;

module.exports = function(callbacks) {
  var createAuthorizationCode = callbacks('createAuthorizationCode', defaultCreate)
    , generateAuthorizationCode = callbacks('generateAuthorizationCode', generateAuthorizationCodeUID)
    , saveAuthorizationCode = callbacks('saveAuthorizationCode');

  // Default workflow
  function defaultCreate(client, redirectURI, user, ares, done) {
    debug('creating auth code for client', client);
    generateAuthorizationCode(function(err, code) {
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
  };

  // List the arguments so oauth2orize can inspect the length
  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    createAuthorizationCode.apply(null, arguments);
  });
}

function generateAuthorizationCodeUID (done) {
  done(null, uid(128));
}
