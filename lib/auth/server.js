
var oauth2orize = require('oauth2orize');

exports = module.exports = function(hashPassword) {
  var server = oauth2orize();

  server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
    hashPassword(username, password, function(err, hash) {
      // TODO check that the passwords match in a secure way so we can avoid timing attacks and such
      done(null, true);
    });
  }));

  return server;
}