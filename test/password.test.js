
var pass = require('../lib/auth/exchanges/password')
  , expect = require('expect.js')
  , MockRequest = require('./mocks').MockRequest
  , MockResponse = require('./mocks').MockResponse;


describe('a password exchange', function() {
  var callbacks = {
    'userByUsername': function(username, done) {
      if (username === 'validuser') return done(null, {});
      done(null, null);
    },
    'verifyPassword': function(user, password, done) {
      if (password === 'validpass') return done(null, true);
      done(null, false);
    },
    'issueToken': function(client, user, scope, done) {
      done(null, 'some-websafe-token-string');
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

  function expect_no_error(err) {
    done(new Error('should not be called'));
  }

  function issues_token(res, done) {
    res.done = function() {
      expect(res._data).to.match(/access_token/);
      expect(res._data).to.match(/bearer/);
      expect(res._data).to.match(/some-websafe-token-string/);
      done();
    }
    return res;
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
    req.body = { username: 'validuser', password: 'validpass' };
    password(req, issues_token(res, done), expect_no_error);
  });

});
