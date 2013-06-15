
var oauth2orize = require('oauth2orize');

exports = module.exports = function(userByUsername, hashPassword) {
  var server = oauth2orize();

  server.exchange(oauth2orize.exchange.password(function(client, username, password, scope, done) {
    userByUsername(username, function(err, user) {
      if(err) return done(err);
      hashPassword(password, user, function(err, hash) {
        if(err) return done(err);
        // TODO check that the passwords match in a secure way so we can avoid timing attacks and such
        done(null, user.passhash === hash);
      });
    });
  }));

  return server;
}