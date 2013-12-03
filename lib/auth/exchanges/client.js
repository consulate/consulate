/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:client');
var oauth2orize = require('oauth2orize');

module.exports = function(callbacks) {
  var issueToken = callbacks('issueToken');

  return oauth2orize.exchange.clientCredentials(function(req, client, scope, done) {
    debug('issuing token for client', client);
    return issueToken(req, client, null, scope, function(err, accessToken, refreshToken, params) {
      debug('issued token for client', client, accessToken);
      done(err, accessToken, refreshToken, params);
    });
  });
}
