/**
 * Module dependencies
 */

var debug = require('simple-debug')('consulate:auth:exchanges:client');
var oauth2orize = require('oauth2orize');
var merge = require('../../utils').merge;

module.exports = function(callbacks) {
  var issueToken = callbacks('issueToken');
  var getAdditionalParams = callbacks('getAdditionalParams', function(req, type, client, user, scope, done) { done(); });

  return oauth2orize.exchange.clientCredentials(function(req, client, scope, done) {
    debug('issuing token for client', client);
    return issueToken(req, client, null, scope, function(err, accessToken, params) {
      debug('issued token for client', client, accessToken);
      if (err) return done(err);

      params = params || {};

      getAdditionalParams(req, 'client', client, null, scope, function(err, additionalParams) {
        if (err) return done(err);
        done(err, accessToken, merge(params, additionalParams));
      });
    });
  });
}
