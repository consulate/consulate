/**
 * Module dependencies.
 */
var express = require('express')
  , oauth2server = require('./oauth2');

var defaultConfig = {
  exchange: {
    password: function(client, redirectURI, user, ares, done) {
      done(null, 'bogus');
    }
  }
};


exports = module.exports = function(config) {
  config = config || defaultConfig;

  var oauth2 = oauth2server(config)
    , app = express();

  app.use(express.bodyParser());
  app.use(app.router);
  app.use(oauth2.errorHandler());

  app.post('/token', oauth2.token());

  return app;
}
