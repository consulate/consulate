
var pass = require('../lib/auth/exchanges/password')
  , expect = require('expect.js');

function MockRequest() {
}

function MockResponse() {
  this._headers = {};
  this._data = '';
}

MockResponse.prototype.setHeader = function(name, value) {
  this._headers[name] = value;
}

MockResponse.prototype.end = function(data, encoding) {
  this._data += data;
  if (this.done) { this.done(); }
}


describe('a password exchange', function() {
  var callbacks = {
    'userByUsername': function(username, done) {
      if (username === 'validuser') return done(null, {'id': 12, 'username': 'validuser'});
      done(null, null);
    },
    'verifyPassword': function(user, password, done) {
      if (password === 'validpass') return done(null, true);
      done(null, false);
    }
  }

  var password, req, res;

  beforeEach(function() {
    password = pass(function(name) {
      return callbacks[name];
    });
    req = new MockRequest();
    res = new MockResponse();
  });

  function invalid_request(done, asserts) {
    return function(err) {
      expect(err).to.be.ok();
      expect(err.code).to.be.ok('invalid_request');
      expect(err.status).to.be(400);
      asserts(err);
      done();
    }
  }

  // NOTE: Missing params are covered by oauth2orize. We deal with data lookups, and test those.

  it('should not accept a bad username', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { username: 'baduser', password: 'validpass' };
    password(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/invalid/);
      expect(err.message).to.match(/cred/);
    }));
  });

  it('should not accept a bad password', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { username: 'validuser', password: 'badpass' };
    password(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/invalid/);
      expect(err.message).to.match(/cred/);
    }));
  });

  it('should accept a good username and password combination', function(done) {
    res.done = function() {
      expect(res._data).to.match(/access_token/);
      done();
    }
    req.body = { username: 'validuser', password: 'validpass' };
    password(req, res, function(err) {
      done(new Error('should not be called'));
    });
  });

});
