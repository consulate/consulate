/**
 * Module dependencies
 */

var express = require('express')
  , proto = require('./application')
  , utils = require('./utils');

/**
 * Expose `createApplication()`
 */

exports = module.exports = createApplication;

/**
 * Create an auth application
 */

function createApplication() {
  var app = express();
  utils.merge(app, proto);
  app.init();
  return app;
};

/**
 * Expose express middleware
 */
exports.middleware = express;
