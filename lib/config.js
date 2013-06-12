
exports = module.exports = {
  exchange: {
    password: function(client, redirectURI, user, ares, done) {
      done(null, 'bogus');
    }
  },
  passport: {
    client: function(clientId, clientSecret, done) {
      if (clientSecret !== 'super secret') { return done(null, null); }
      return done(null, { id: clientId });
    }
  }
}
