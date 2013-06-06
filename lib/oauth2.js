
var oauth2orize = require('oauth2orize');

exports = module.exports = function(config) {
  var server = oauth2orize();
  if (config && config.exchange && config.exchange.password) {
    server.exchange(oauth2orize.exchange.password(config.exchange.password));
  }

  return server;
}