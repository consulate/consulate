/**
 * Module dependencies.
 */

var debug = require('debug')('authplay:application')
  , express = require("express")
  , oauth2server = require('./auth/server')
  , clientAuth = require('./auth/client')
  , passport = require('passport');

/**
 * Application prototype.
 */

var app = exports = module.exports = {};

/**
 * Initialize the server.
 *
 *
 * @api private
 */

app.init = function() {
  this.callbacks = {};
  this.viewCallbacks = {};
  this.defaultConfiguration();
};

/**
 * Initialize application configuration.
 *
 * @api private
 */

app.defaultConfiguration = function() {
  var self = this;

  // default settings
  this.disable('x-powered-by');

  // Setup our oauth modules
  var oauth2 = oauth2server(self.callback('client'))
    , client = clientAuth(self.callback('hashPassword'));

  // Add our middleware
  self
    .use(express.bodyParser())
    .use(passport.initialize())
    .use(self.router)
    .use(oauth2.errorHandler());

  // API
  self.post('/token', client.verifyApp(), oauth2.token());

  // UI
  self.get("/login", function(req, res, next) {
    // TODO populate the `locals` with the needed info

    // Call the registered callback
    self.viewCallbacks.login(req, res, next);
  });

  self.get("/dialog/authorize", function(req, res, next) {
    // TODO populate the `locals` with the needed info
    res.locals({
      scopes: ["user:name"],
      clientName: "Test Application",
      clientDescription: "A testing client helping oauth implementors one app at a time"
    });

    // Call the registered callback
    self.viewCallbacks.authorize(req, res, next);
  });
};

/**
 * Get a callback function that has been registered
 */
app.callback = function(name) {
  var self = this;

  // Create a proxy function so when the callback updates
  // all of the modules that need this callback keep
  // the same reference
  return function() {
    if(!self.callbacks[name]) throw new Error("'"+name+"' callback not found");
    self.callbacks[name].apply(null, arguments);
  };
};

/**
 * Register a callback for the allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

app.scopes = function(fn) {
  this.callbacks.scopes = fn;
};

/**
 * Register a callback for the current secrets to
 * be used with `simple-secrets`
 *
 * @param {Function} fn
 * @api public
 */

app.secrets = function(fn) {
  this.callbacks.secrets = fn;
};

/**
 * Register a callback to find a user by ID
 *
 * @param {Function} fn
 * @api public
 */

app.user = function(fn) {
  this.callbacks.user = fn;
};

/**
 * Register a callback to find a user by username
 *
 * @param {Function} fn
 * @api public
 */

app.userByUsername = function(fn) {
  this.callbacks.userByUsername = fn;
};

/**
 * Register a callback to list a user's allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

app.allowedUserScopes = function(fn) {
  this.callbacks.allowedUserScopes = fn;
};

/**
 * Register a callback to hash a user provided password
 *
 * @param {Function} fn
 * @api public
 */

app.hashPassword = function(fn) {
  this.callbacks.hashPassword = fn;
};

/**
 * Register a callback to lookup a client by clientID
 *
 * @param {Function} fn
 * @api public
 */

app.client = function(fn) {
  this.callbacks.client = fn;
};

/**
 * Register a callback to lookup an authorization code with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

app.authorizationCode = function(fn) {
  this.callbacks.authorizationCode = fn;
};

/**
 * Register a callback to save an authorization code
 *
 * @param {Function} fn
 * @api public
 */

app.saveAuthorizationCode = function(fn) {
  this.callbacks.saveAuthorizationCode = fn;
};

/**
 * Register a callback to lookup an access token with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

app.accessToken = function(fn) {
  this.callbacks.accessToken = fn;
};

/**
 * Register a callback to save an access token
 *
 * @param {Function} fn
 * @api public
 */

app.saveAccessToken = function(fn) {
  this.callbacks.saveAccessToken = fn;
};

/**
 * Register a callback to render the 'login' page
 *
 * @param {Function} fn
 * @api public
 */

app.loginView = function(fn) {
  this.viewCallbacks.login = fn;
};

/**
 * Register a callback to render the 'authorize' page
 *
 * @param {Function} fn
 * @api public
 */

app.authorizeView = function(fn) {
  this.viewCallbacks.authorize = fn;
};
