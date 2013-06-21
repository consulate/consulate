/**
 * Module dependencies
 */
var expect = require('expect.js')
  , app = require('./fixtures/integration')
  , request = require('supertest')
  , parse = require('url').parse;

describe('consulate integration', function() {

  var redirect_uri = 'http://localhost:5000/auth/callback';

  it('should support a web server exchange', function(done) {
    var client_id = 'validClient'
      , client_secret = 'validSecret';

    userLogin(client_id, redirect_uri, 'code', function(err, code) {
      if (err) return done(err);
      request(app)
        .post('/token')
        .auth(client_id, client_secret)
        .send({grant_type: 'authorization_code', code: code, redirect_uri: redirect_uri})
        .end(function(err, res) {
          if (err) return done(err);
          if (res.error) return done(new Error(res.text));
          expect(res.body.access_token).to.be.ok();
          done();
        });
    });
  });

  it('should support a public client exchange', function(done) {
    var client_id = 'publicClient';

    userLogin(client_id, redirect_uri, 'code', function(err, code) {
      if (err) return done(err);
      request(app)
        .post('/token')
        .send({grant_type: 'authorization_code', code: code, redirect_uri: redirect_uri, client_id: client_id})
        .end(function(err, res) {
          if (err) return done(err);
          if (res.error) return done(new Error(res.text));
          expect(res.body.access_token).to.be.ok();
          done();
        });
    });
  });

  it('should support a password exchange', function(done) {
    var client_id = 'validClient'
      , client_secret = 'validSecret';

    request(app)
      .post('/token')
      .auth(client_id, client_secret)
      .send({grant_type: 'password', username: 'validUser', password: 'validPass'})
      .end(function(err, res) {
        if (err) return done(err);
        if (res.error) return done(new Error(res.text));
        expect(res.body.access_token).to.be.ok();
        done();
      });
  });

  it('should support a client token exchange');
});

/**
 * Simulate logging in a user and gettings an authorization code
 */

function userLogin(client_id, redirect_uri, response_type, done) {
  var agent = request.agent(app);

  // Try to get a user credential for a client
  agent
    .get('/authorize')
    .redirects(1)
    .query({client_id: client_id, redirect_uri: redirect_uri, response_type: response_type})
    .expect('login')
    .end(function(err, res) {
      if (err) return done(err);
      if (res.error) return done(new Error(res.text));

      // Post our username/password
      agent
        .post('/login')
        .redirects(1)
        .send({'username': 'validUser', 'password': 'validPass'})
        .end(function(err, res) {
          if (err) return done(err);
          if (res.error) return done(new Error(res.text));

          // Make sure we're on /authorize
          expect(res.req.path).to.contain('/authorize');

          var transaction = res.body.transaction
            , action = res.body.action;

          // There's some lame race condition in the superagent cookie stuff somewhere
          process.nextTick(submit);

          // Submit the decision
          function submit() {
            agent
              .post(action)
              .redirects(0)
              .send({transaction_id: transaction, allow: true})
              .end(function(err, res) {
                if (err) return done(err);
                if (res.error) return done(new Error(res.text));

                // Get the authorization code
                var code = parse(res.headers.location).query.replace('code=', ''); // TODO get a urlencoded parser

                done(null, code);
              });
          };
        });
    });
};