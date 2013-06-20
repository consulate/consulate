/**
 * Module dependencies
 */


var users = [
  {
    id: 'user1',
    username: 'validUser',
    passhash: 'validPass',
    scopes: '*'
  }
];

var clients = [
  {
    id: 'validClient',
    name: 'My Application',
    description: 'A really cool application',
    secret: 'super+secret',
    redirect_uri: ['http://localhost:5000/auth/callback'],
    scopes: ['user:name', 'user:email'],
    optional_scopes: ['user:age']
  }
];

var authorizationCodes = {};

exports.getUser = function(id, cb) {
  cb(null, find(users, function(user) {
    return user.id == id;
  }));
};

exports.getUserByUsername = function(username, cb) {
  var user = find(users, function(user) {
    return user.username == username;
  });
  cb(null, user);
};

exports.getClient = function(id, cb) {
  cb(null, find(clients, {id: id}));
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

function find(list, fn) {
  for (var i = 0; i < list.length; i++) {
    if (fn(list[i])) return list[i];
  }
  return null;
};