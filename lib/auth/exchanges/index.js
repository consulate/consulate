/**
 * Module dependencies
 */

var exchanges = {
  code: require('./code'),
  password: require('./password')
};

module.exports = function(server, callbacks) {
  return Object.keys(exchanges).map(function(type) {
    var exchange = exchanges[type](callbacks);
    server.exchange(exchange);
    return exchange;
  });
};
