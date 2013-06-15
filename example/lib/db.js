/**
 * Module dependencies
 */

var users = {
  '1': {username: 'timshadel', passhash: '123', scopes: '*'}
};

var clients = {
  '123': {
    secret: 'super+secret',
    callbacks: ['http://localhost:5000/auth/callback'],
    scopes: ['user:name', 'user:email'],
    optional_scopes: ['user:age']
  }
};

var authorizationCodes = {};

var accessTokens = {};

exports.getUser = function(id, cb) {
  cb(null, users[id]);
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
    redirect_uri: redirectURI
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
