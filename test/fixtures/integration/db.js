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
    secret: 'validSecret',
    redirect_uri: ['http://localhost:5000/auth/callback'],
    scope: ['user:name', 'user:email', 'user:age']
  },
  {
    id: 'publicClient',
    redirect_uri: ['http://localhost:5000/auth/callback'],
    scopes: ['user:name', 'user:email']
  }
];

var authorizationCodes = [];

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
  cb(null, find(clients, function(client) {
    return client.id == id;
  }));
};

exports.isValidClientRedirectURI = function(client, uri, cb) {
  cb(null, client.redirect_uri.indexOf(uri) > -1);
}

exports.getAuthorizationCode = function(id, cb) {
  cb(null, authorizationCodes[id]);
};

exports.createAuthorizationCode = function(client, redirectURI, user, ares, cb) {
  var authCode = {
    user_id: user.id,
    client_id: client.id,
    redirect_uri: redirectURI
  };
  var code = authorizationCodes.length;
  authorizationCodes.push(authCode);
  cb(null, ''+code);
};

exports.invalidateAuthorizationCode = function(code, cb) {
  delete authorizationCodes[code]
  cb();
};

function find(list, fn) {
  for (var i = 0; i < list.length; i++) {
    if (fn(list[i])) return list[i];
  }
  return null;
};