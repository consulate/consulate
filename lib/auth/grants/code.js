/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:grants:code')
  , oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var createAuthorizationCode = callbacks('createAuthorizationCode');

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    debug('creating auth code for client', client, 'and user', user);
    createAuthorizationCode(client, redirectURI, user, ares, function(err, code) {
      debug('created auth code', code);
      done(err, code);
    });
  });
}
