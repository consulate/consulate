/**
 * Test dependencies
 */
var app = require("../")
  , expect = require("expect.js")
  , supertest = require("supertest");

describe("an access token", function() {

  it("should be issued when requested", function(done) {
    supertest(app)
      .post("/token")
      .send({ grant_type: 'password' })
      .send({ username: 'user' })
      .send({ password: 'pass' })
      .expect(200)
      .expect(/access_token/, done);
  });

});
