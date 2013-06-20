/**
 * Module dependencies
 */
var expect = require('expect.js')
  , app = require('./fixtures/integration')
  , request = require('supertest');

describe('consulate integration', function() {
  it('should redirect from /authorize to /login without a valid session', function(done) {
    request(app)
      .get('/authorize')
      .expect(302, done);
  });

  it('should return a valid response for /login', function(done) {
    request(app)
      .get('/login')
      .expect('login')
      .expect(200, done);
  });

  it('should support a web server exchange', function(done) {
    var agent = request.agent(app);

    // Try to get a user credential for a client
    agent
      .get('/authorize')
      .query({client_id: 'validClient'})
      .expect(302)
      .end(function(err, res) {
        if (err) return done(err);
        if (res.error) return done(new Error(res.text));

        // Get the login page
        expect(res.headers.location).to.eql('/login');
        agent
          .get(res.headers.location)
          .expect(200)
          .expect('login')
          .end(function(err, res) {
            if (err) return done(err);
            if (res.error) return done(new Error(res.text));

            // Post our username/password
            agent
              .post('/login')
              .send({'username': 'validUser', 'password': 'validPass'})
              .expect(302)
              .end(function(err, res) {
                if (err) return done(err);
                if (res.error) return done(new Error(res.text));

                // Redirect back to /authorize
                expect(res.headers.location).to.contain('/authorize');
                agent
                  .get(res.headers.location)
                  .expect(200)
                  .end(function(err, res) {
                    if (err) return done(err);
                    if (res.error) return done(new Error(res.text));

                    // TODO submit the decision
                    // TODO get an auth code
                    // TODO exchange an auth code for a token
                  });
              });
          })
      });
  });
});
