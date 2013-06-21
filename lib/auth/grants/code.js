/**
 * Module dependencies
 */

var debug = require('debug')('consulate:auth:grants:code')
  , oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var createAuthorizationCode = callbacks('createAuthorizationCode');

  return oauth2orize.grant.code(function(client, redirectURI, user, ares, done) {
    createAuthorizationCode.apply(null, arguments);
  });
}
