/**
 * Module dependencies
 */
var consulate = require("../../..")
  , db = require('./db')
  , express = require('express')
  , domain = require('domain');

var app = consulate({session: {
  secret: 'consulate',
  key: '_oauth2_session'
}});

/**
 * DB callbacks
 */

app
  .user(db.getUser)
  .userByUsername(db.getUserByUsername)
  .client(db.getClient)
  .authorizationCode(db.getAuthorizationCode)
  .saveAuthorizationCode(db.saveAuthorizationCode)
  .invalidateAuthorizationCode(db.invalidateAuthorizationCode)

/**
 * Misc callbacks
 */

app
  .verifyPassword(function(user, password, done) {
    done(null, password == 'validPass');
  })
  .issueToken(function(client, user, scope, done) {
    done(null, JSON.stringify({
      client: client,
      user: user,
      scope: scope
    }));
  });

/**
 * Views
 */

app
  .loginView(function(req, res) {
    res.send('login');
  })
  .authorizeView(function(req, res) {
    res.send('authorize');
  });

var server = module.exports = express();

server.use(function(req, res) {
  var reqd = domain.create();

  // Add req and res the the request domain
  reqd.add(req);
  reqd.add(res);

  // Error handler
  reqd.on('error', function(err) {
    console.error(err);
  });

  // Dispose the domain
  res.on('close', function() {
    reqd.dispose();
  });

  reqd.bind(app)(req, res);
});
