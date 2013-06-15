/**
 * Module dependencies.
 */

var debug = require('debug')('authplay:application')
  , express = require('express')
  , passport = require('passport')
  , simpleSecrets = require('simple-secrets')
  , login = require('connect-ensure-login')
  , oauth2server = require('./auth/server')
  , registerGrants = require('./auth/grants')
  , registerExchanges = require('./auth/exchanges')
  , clientAuth = require('./auth/client')
  , userAuth = require('./auth/user');

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

app.init = function(opts) {
  this.callbacks = {};
  this.viewCallbacks = {};
  this.defaultConfiguration(opts);
};

/**
 * Initialize application configuration.
 *
 * @api private
 */

app.defaultConfiguration = function(opts) {
  var self = this
    , callbacks = self.callback.bind(self);

  // Check options
  if (!opts.session) throw new Error("Missing 'session' options");

  // default settings
  self.disable('x-powered-by');

  // Setup our oauth modules
  var oauth2 = oauth2server(callbacks)
    , grants = registerGrants(oauth2, callbacks)
    , exchanges = registerExchanges(oauth2, callbacks)
    , client = clientAuth(callbacks)
    , user = userAuth(callbacks);

  // Add our middleware
  self
    .use(express.logger('dev'))
    .use(express.bodyParser())
    .use(express.cookieParser())
    .use(express.cookieSession(opts.session))
    .use(passport.initialize())
    .use(passport.session())
    .use(self.router);

  // API
  self
    .post('/token', client.verifyApp(), oauth2.token(), errorLogger, oauth2.errorHandler());

  // UI
  self
    .get('/login', self.viewCallback('login'))
    .post('/login', user.handleLogin(), self.viewCallback('login'));

  self
    .get('/authorize', login.ensureLoggedIn(), oauth2.authorizeClient(), oauth2.authorizeLocals(), self.viewCallback('authorize'))
    .post('/authorize/decision', login.ensureLoggedIn(), oauth2.decision());
};

/**
 * Log errors from oauth2 api endpoints
 */
function errorLogger(err, req, res, next) {
  console.error(err.stack || err);
  next(err);
};

/**
 * Get a callback function that has been registered
 */
app.callback = function(name) {
  var self = this;

  // Create a proxy function so we can return a callback
  // before it's actually defined
  return function() {
    if(!self.callbacks[name]) throw new Error("'"+name+"' callback not found");
    return self.callbacks[name].apply(null, arguments);
  };
};

/**
 * Get a callback function that has been registered
 */
app.viewCallback = function(name) {
  var self = this;

  // Create a proxy function so we can return a callback
  // before it's actually defined
  return function() {
    if(!self.viewCallbacks[name]) throw new Error("'"+name+"' view callback not found");
    return self.viewCallbacks[name].apply(null, arguments);
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
  var self = this
    , senders = [];

  function loadSecrets() {
    fn(function(err, secrets) {
      secrets.forEach(function(key) {
        var key = new Buffer(key, 'hex')
          , sender = simpleSecrets(key);
        senders.push(sender);
      });
    });
  };

  function encryptMessage(message) {
    if (!senders.length) loadSecrets();
    if (!senders.length) throw new Error("Unable to create a simple-secrets sender");
    // Use the first one
    return senders[0].pack(message);
  };

  this.callbacks.secrets = encryptMessage;
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
