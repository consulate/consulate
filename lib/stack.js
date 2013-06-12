/**
 * Module dependencies.
 */
var express = require('express')
  , oauth2server = require('./oauth2')
  , clientAuth = require('./auth/client')
  , passport = require('passport');

exports = module.exports = function(config) {
  config = config || {};

  var oauth2 = oauth2server(config)
    , client = clientAuth(config)
    , app = express();

  app.use(express.bodyParser());
  app.use(passport.initialize());
  app.use(app.router);
  app.use(oauth2.errorHandler());

  app.post('/token', client.verifyApp(), oauth2.token());

  return app;
}
