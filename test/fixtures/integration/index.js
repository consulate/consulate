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
  .getUser(db.getUser)
  .getUserByUsername(db.getUserByUsername)
  .getClient(db.getClient)
  .getAuthorizationCode(db.getAuthorizationCode)
  .createAuthorizationCode(db.createAuthorizationCode)
  .invalidateAuthorizationCode(db.invalidateAuthorizationCode)
  .verifyClientRedirectURI(db.isValidClientRedirectURI);

/**
 * Misc callbacks
 */

app
  .getScopes(function(done) {
    done(null, []);
  })
  .getAllowedUserScopes(function(user, done) {
    done(null, user.scopes);
  })
  .getUserDecision(function(user, client, done) {
    done(null, null);
  })
  .saveUserDecision(function(user, client, decision, done) {
    done();
  })
  .verifyPassword(function(user, password, done) {
    done(null, password == 'validPass');
  })
  .issueToken(function(client, user, scope, done) {
    done(null, JSON.stringify({
      client: client.id,
      user: (user || {}).id,
      scope: scope
    }));
  })
  .getRefreshToken(function(refreshToken, done) {
    done(null, {
      client_id: 'validClient',
      user_id: 'user1'
    });
  })
  .createRefreshToken(function(client, user, scope, done) {
    done(null, 'new-refresh-token');
  })
  .invalidateRefreshToken(function(refreshToken, done) {
    done();
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
