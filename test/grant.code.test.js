
var codeGrant = require('..').grants.code
  , expect = require('expect.js')
  , MockRequest = require('./mocks').MockRequest
  , MockResponse = require('./mocks').MockResponse;


describe('a code grant', function() {

  var callbacks = {
    'createAuthorizationCode': function(client, redirectURI, user, ares, done) {
      if (client.id === 'validClientId') return done(null, 'validCode');
      done(null, null);
    }
  }

  var code, req, res;

  beforeEach(function() {
    code = codeGrant(function(name) {
      return callbacks[name];
    });
    req = new MockRequest();
    res = new MockResponse();
    invalidatedCodes = [];
  });

  function expect_no_error(done) {
    return function(err) {
      done(new Error('should not be called. err: ' + err));
    }
  }

  function issues_code(res, done) {
    res.done = function() {
      expect(res._redirect).to.match(/validRedirectURI/);
      expect(res._redirect).to.match(/code=validCode/);
      done();
    }
    return res;
  }

  // NOTE: Missing params are covered by oauth2orize. We deal with data lookups, and test those.

  it('should issue a code to a valid redirect uri from a known client', function(done) {
    var txn = {
      req: req,
      client: { id: 'validClientId' },
      redirectURI: 'validRedirectURI',
      res: res,
    };
    res.allow = true;
    code.response(txn, issues_code(res, done), expect_no_error(done));
  });

});
