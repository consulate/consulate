/**
 * Module dependencies
 */

var express = require('express');
var proto = require('./application');
var utils = require('./utils');

/**
 * Expose `createApplication()`
 */

exports = module.exports = createApplication;

/**
 * Create an auth application
 */

function createApplication(opts) {
  var app = express();
  utils.merge(app, proto);
  app.init(opts || {});
  return app;
};

/**
 * Expose express middleware
 */

exports.middleware = express;

/**
 * Expose the exchanges
 */

exports.exchanges = require('./auth/exchanges').exchanges;

/**
 * Expose the grants
 */

exports.grants = require('./auth/grants').grants;
