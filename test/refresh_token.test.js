/**
 * Module dependencies
 */

var rt = require('..').exchanges.refresh_token;
var expect = require('expect.js');
var MockRequest = require('./mocks').MockRequest;
var MockResponse = require('./mocks').MockResponse;

describe('a password exchange', function() {
  var callbacks = {
    'getUser': function(req, userId, done) {
      if (userId === 'user123') return done(null, {});
      done(null, null);
    },
    'getRefreshToken': function(req, refreshToken, done) {
      if (refreshToken === 'badtoken') return done(null, false);
      done(null, {
        client_id: 'validclient',
        user_id: 'user123'
      });
    },
    'issueTokens': function(req, type, client, user, scope, done) {
      done(null, 'some-websafe-token-string', 'valid-refresh-token');
    },
    'invalidateRefreshToken': function(req, refreshToken, done) {
      done();
    }
  };

  var refreshToken, req, res;

  beforeEach(function() {
    refreshToken = rt(function(name) {
      return callbacks[name];
    });
    req = new MockRequest();
    res = new MockResponse();
  });

  function invalid_request(done, asserts) {
    return function(err) {
      expect(err).to.be.ok();
      expect(err.code).to.be.ok('invalid_request');
      expect(err.status).to.be(403);
      asserts(err);
      done();
    }
  }

  function expect_no_error(done) {
    return function(err) {
      done(new Error('should not be called. Error: ' + err));
    };
  }

  function issues_token(res, done) {
    res.done = function() {
      expect(res._data).to.match(/access_token/);
      expect(res._data).to.match(/Bearer/);
      expect(res._data).to.match(/some-websafe-token-string/);
      expect(res._data).to.match(/refresh_token/);
      expect(res._data).to.match(/valid-refresh-token/);
      done();
    }
    return res;
  }

  // NOTE: Missing params are covered by oauth2orize. We deal with data lookups, and test those.

  it('should not accept a refresh token', function(done) {
    res.done = function() {
      done(new Error('should not be called. Error: ' + err));
    }
    req.body = { refresh_token: 'badtoken' };
    refreshToken(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/Invalid/);
      expect(err.message).to.match(/refresh/);
    }));
  });

  it('should not accept a refresh token from a client mismatch', function(done) {
    res.done = function() {
      done(new Error('should not be called. Error: ' + err));
    }
    req.body = { refresh_token: 'validtoken' };
    req.user = { id: 'invalidclient' };
    refreshToken(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/Invalid/);
      expect(err.message).to.match(/refresh/);
    }));
  });

  it('should accept a good refresh token', function(done) {
    req.body = { refresh_token: 'validtoken' };
    req.user = { id: 'validclient' };
    refreshToken(req, issues_token(res, done), expect_no_error(done));
  });

});
