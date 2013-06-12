
var oauth2server = require('../lib/auth/server')
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


describe('an oauth2 server', function() {

  describe('with no configuration', function() {
    var server, req, res;

    beforeEach(function() {
      server = oauth2server();
      req = new MockRequest();
      res = new MockResponse();
      res.done = function() {
        done(new Error('should not be called'));
      }
    });

    function unsupported_grant_type(done) {
      return function(err) {
        expect(err).to.be.ok();
        expect(err.code).to.be.ok('unsupported_grant_type');
        expect(err.status).to.be(400);
        done();
      }
    }

    it('should not recognize authorization_code grants', function(done) {
      var token = server.token();
      req.body = { grant_type: 'authorization_code', code: 'abc123' };      
      token(req, res, unsupported_grant_type(done));
    });

    it('should not recognize code grants', function(done) {
      var token = server.token();
      req.body = { grant_type: 'code', code: 'abc123' };
      token(req, res, unsupported_grant_type(done));
    });

    it('should not recognize password grants', function(done) {
      var token = server.token();
      req.body = { grant_type: 'password', code: 'abc123' };
      token(req, res, unsupported_grant_type(done));
    });

  });

  describe('with password exchange configuration', function() {
    var server, req, res;

    beforeEach(function() {
      config = { exchange: { password: function(client, redirectURI, user, ares, done) {
          done(null, 'bogus');
      }}};
      server = oauth2server(config);
      req = new MockRequest();
      res = new MockResponse();
    });

    function no_error(done) {
      return function(err) {
        done(new Error('should not be called: ' + err));
      }
    }

    function access_token_issued(res, done) {
      res.done = function() {
        expect(res._data).to.be('{"access_token":"bogus","token_type":"bearer"}');
        done();
      }
      return res;
    }

    it('should recognize password grants', function(done) {
      var token = server.token();
      req.body = { grant_type: 'password', username: 'user', password: 'pass' };
      token(req, access_token_issued(res, done), no_error(done));
    });

  });

});