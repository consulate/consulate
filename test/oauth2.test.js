
var oauth2server = require('../lib/oauth2')
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

    var server;
    beforeEach(function() {
      server = oauth2server();
    });

    it('should not recognize authorization_code grants', function(done) {
      var token = server.token();
      expect(server).to.be.an('object');

      var self = this;
      var req = new MockRequest();
      req.body = { grant_type: 'authorization_code', code: 'abc123' };
      
      var res = new MockResponse();
      res.done = function() {
        done(new Error('should not be called'));
      }

      function next(err) {
        expect(err).to.be.ok();
        expect(err.code).to.be.ok('unsupported_grant_type');
        expect(err.status).to.be(400);
        done();
      }

      process.nextTick(function () {
        token(req, res, next);
      });
    });

    it('should not recognize code grants', function(done) {
      var token = server.token();
      expect(server).to.be.an('object');

      var self = this;
      var req = new MockRequest();
      req.body = { grant_type: 'code', code: 'abc123' };
      
      var res = new MockResponse();
      res.done = function() {
        done(new Error('should not be called'));
      }

      function next(err) {
        done();
      }

      process.nextTick(function () {
        token(req, res, next);
      });
    });

    it('should not recognize password grants', function(done) {
      var token = server.token();
      expect(server).to.be.an('object');

      var self = this;
      var req = new MockRequest();
      req.body = { grant_type: 'password', code: 'abc123' };
      
      var res = new MockResponse();
      res.done = function() {
        done(new Error('should not be called'));
      }

      function next(err) {
        done();
      }

      process.nextTick(function () {
        token(req, res, next);
      });
    });

  });

});