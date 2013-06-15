/**
 * Module dependencies
 */

var find = require('find');

var users = [
  // password = testing123
  {
    id: 0,
    username: 'timshadel',
    passhash: 'c00fdd087376f0a11a5ad70f1df471913cd277d7ffe2f3d2f891c8a400c373e09ac6ca25733b820e65262eecfa2ede0aa6dcaf78acb9d1cc2441f51dffacddd1',
    scopes: '*'
  }
];

var clients = {
  '123': {
    name: 'My Application',
    description: 'A really cool application',
    secret: 'super+secret',
    return_uri: ['http://localhost:5000/auth/callback'],
    scopes: ['user:name', 'user:email'],
    optional_scopes: ['user:age']
  }
};

var authorizationCodes = {};

var accessTokens = {};

exports.getUser = function(id, cb) {
  cb(null, users[id]);
};

exports.getUserByUsername = function(username, cb) {
  var user = find(users, {username: username});
  cb(null, user);
};

exports.getClient = function(id, cb) {
  cb(null, clients[id]);
};

exports.getAuthorizationCode = function(id, cb) {
  cb(null, authorizationCodes[id]);
};

exports.saveAuthorizationCode = function(code, userID, clientID, redirectURI, cb) {
  authorizationCodes[code] = {
    user_id: userID,
    client_id: clientID,
    return_uri: redirectURI
  };
  cb();
};

exports.getAccessToken = function(id, cb) {
  cb(null, accessTokens[id]);
};

exports.saveAccessToken = function(code, userID, clientID, cb) {
  accessTokens[code] = {
    user_id: userID,
    client_id: clientID
  };
  cb();
};
