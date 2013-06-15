/**
 * Module dependencies
 */

var grants = {
  code: require('./code')
};

module.exports = function(server, callbacks) {
  return Object.keys(grants).map(function(type) {
    var grant = grants[type](callbacks);
    server.grant(grant);
    return grant;
  });
};
