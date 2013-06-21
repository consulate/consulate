/**
 * Module dependencies
 */

exports = module.exports = function(server, callbacks) {
  return Object.keys(exports.grants).map(function(type) {
    var grant = exports.grants[type](callbacks);
    server.grant(grant);
    return grant;
  });
};

exports.grants = {
  code: require('./code')
};