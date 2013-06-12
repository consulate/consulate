/**
 * Test dependencies
 */
var app = require("../")
  , expect = require("expect.js")
  , supertest = require("supertest");

describe("POST /token", function() {

  it("should require client authentication", function(done) {
    supertest(app)
      .post("/token")
      .send({ grant_type: 'password' })
      .send({ username: 'user' })
      .send({ password: 'pass' })
      .expect(401, done);
  });

  it("should require valid client credentials", function(done) {
    supertest(app)
      .post("/token")
      .auth('evil', 'app')
      .send({ grant_type: 'password' })
      .send({ username: 'user' })
      .send({ password: 'pass' })
      .expect(401, done);
  });

  it("should issue an access_token to any request with basic auth", function(done) {
    supertest(app)
      .post("/token")
      .auth('client', 'super secret')
      .send({ grant_type: 'password' })
      .send({ username: 'user' })
      .send({ password: 'pass' })
      .expect(200)
      .expect(/access_token/, done);
  });

  it("should issue an access_token to any request with client creds in the body", function(done) {
    supertest(app)
      .post("/token")
      .send({ grant_type: 'password' })
      .send({ username: 'user' })
      .send({ password: 'pass' })
      .send({ client_id: 'client' })
      .send({ client_secret: 'super secret' })
      .expect(200)
      .expect(/access_token/, done);
  });

});
