/**
 * Module dependencies
 */

var exchanges = {
  code: require("./code"),
  password: require("./password")
};

module.exports = function(server, callbacks) {
  return Object.keys(exchanges).map(function(type) {
    return exchanges[type](server, callbacks);
  });
};
