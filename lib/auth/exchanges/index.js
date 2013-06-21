/**
 * Module dependencies
 */

exports = module.exports = function(server, callbacks) {
  return Object.keys(exports.exchanges).map(function(type) {
    var exchange = exports.exchanges[type](callbacks);
    server.exchange(exchange);
    return exchange;
  });
};

exports.exchanges = {
  code: require('./code'),
  password: require('./password')
};