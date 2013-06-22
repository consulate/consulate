/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:client')
  , oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var issueToken = callbacks('issueToken');

  return oauth2orize.exchange.clientCredentials(function(client, scope, done) {
    debug('issuing token for client', client);
    return issueToken(client, null, scope, function(err, accessToken, refreshToken, params) {
      debug('issued token for client', client, accessToken);
      done(err, accessToken, refreshToken, params);
    });
  });
}