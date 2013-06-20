
var codeEx = require('../lib/auth/exchanges/code')
  , expect = require('expect.js')
  , MockRequest = require('./mocks').MockRequest
  , MockResponse = require('./mocks').MockResponse;


describe('a code exchange', function() {
  // Store our invalidated auth codes
  var invalidatedCodes;

  var callbacks = {
    'authorizationCode': function(code, done) {
      var fullCode = {client_id: 'validClientId', user_id: 'validUserId', redirect_uri: 'validRedirectUri'};
      if (~invalidatedCodes.indexOf(code)) return done(null, false);
      if (code === 'validCode') return done(null, fullCode);
      done(null, null);
    },
    'user': function(userId, done) {
      if (userId === 'validUserId') return done(null, {});
      done(null, null);
    },
    'issueToken': function(client, user, scope, done) {
      done(null, 'some-websafe-token-string');
    },
    'invalidateAuthorizationCode': function(code, done) {
      invalidatedCodes.push(code);
      done(null);
    }
  }

  var password, req, res;

  beforeEach(function() {
    code = codeEx(function(name) {
      return callbacks[name];
    });
    req = new MockRequest();
    res = new MockResponse();
    invalidatedCodes = [];
  });

  function invalid_request(done, asserts) {
    return function(err) {
      expect(err).to.be.ok();
      expect(err.code).to.be('invalid_grant');
      expect(err.status).to.be(400);
      asserts(err);
      done();
    }
  }

  function expect_no_error(done) {
    return function(err) {
      done(new Error('should not be called. err: ' + err));
    }
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

  it('should not accept a bad code', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { code: 'badCode', redirect_uri: 'validRedirectUri' };
    // During exchanges, the "user" is the client app
    req.user = { id: 'validClientId' };
    code(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/invalid/);
      expect(err.message).to.match(/code/);
    }));
  });

  it('should not accept a bad redirect uri', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { code: 'validCode', redirect_uri: 'badRedirectUri' };
    // During exchanges, the "user" is the client app
    req.user = { id: 'validClientId' };
    code(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/invalid/);
      expect(err.message).to.match(/code/);
    }));
  });

  it('should not accept codes from an unknown client app', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { code: 'validCode', redirect_uri: 'validRedirectUri' };
    // During exchanges, the "user" is the client app
    code(req, res, function(err) {
      expect(err).to.be.ok();
      expect(err.code).to.be('invalid_client');
      expect(err.status).to.be(401);
      expect(err.message).to.match(/client/);
      done();
    });
  });

  it('should not accept codes from a different client app than the one to which they were issued', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { code: 'validCode', redirect_uri: 'validRedirectUri' };
    // During exchanges, the "user" is the client app
    req.user = { id: 'otherClientId' };
    code(req, res, invalid_request(done, function(err) {
      expect(err.message).to.match(/invalid/);
      expect(err.message).to.match(/code/);
    }));
  });

  it('should not accept an invalidated code', function(done) {
    res.done = function() {
      done(new Error('should not be called'));
    }
    req.body = { code: 'validCode', redirect_uri: 'validRedirectUri' };
    req.user = { id: 'validClientId' };
    code(req, issues_token(res, function() {
      code(req, res, invalid_request(done, function(err) {
        expect(err.message).to.match(/invalid/);
        expect(err.message).to.match(/code/);
      }));
    }), expect_no_error(done));
  });

  it('should accept a good code with a valid redirect uri from a known client', function(done) {
    req.body = { code: 'validCode', redirect_uri: 'validRedirectUri' };
    // During exchanges, the "user" is the client app
    req.user = { id: 'validClientId' };
    code(req, issues_token(res, done), expect_no_error(done));
  });

});
