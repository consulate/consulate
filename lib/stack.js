/**
 * Module dependencies.
 */
var express = require('express')
  , oauth2server = require('./oauth2');

exports = module.exports = function(config) {
  config = config || {};

  var oauth2 = oauth2server(config)
    , app = express();

  app.use(express.bodyParser());
  app.use(app.router);
  app.use(oauth2.errorHandler());

  app.post('/token', oauth2.token());

  return app;
}
