/**
 * Module dependencies
 */
var consulate = require("../../..")
  , db = require('./db')
  , express = require('express');

var app = module.exports = consulate({session: {
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
  .createAuthorizationCode(db.createAuthorizationCode)
  .invalidateAuthorizationCode(db.invalidateAuthorizationCode)

/**
 * Misc callbacks
 */

app
  .scopes(function(done) {
    done(null, []);
  })
  .allowedUserScopes(function(user, done) {
    done(null, user.scopes);
  })
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
    res.send({
      transaction: res.locals.transaction,
      action: res.locals.action
    });
  });
