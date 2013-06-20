/**
 * Module dependencies.
 */

var debug = require('debug')('authplay:application')
  , express = require('express')
  , passport = require('passport')
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
    .post('/login', self.authenticate(user), self.viewCallback('login'));

  self
    .get('/authorize', login.ensureLoggedIn(), oauth2.authorizeClient(), oauth2.authorizeLocals(), self.viewCallback('authorize'))
    .post('/authorize/decision', login.ensureLoggedIn(), oauth2.decision());
};

/**
 * Authenticate a user in with the given passport strategy
 */

app.authenticate = function(strategy, lookup) {

  // Default to just passing the user through
  lookup = lookup || function(user, fn) { fn(null, user) };

  return function(req, res, next) {
    // We want to do some custom handling here
    passport.authenticate(strategy, function(err, foreignUser, info) {
      if (err) return next(err);

      // We couldn't find the user or the password was invalid
      if (!foreignUser) {
        res.locals({loginInfo: info || 'Invalid username/password'});
        return next();
      }

      lookup(foreignUser, function(err, user) {
        req.logIn(user, function(err) {
          if (err) return next(err);

          var returnTo = req.session.returnTo;
          // Delete it
          delete req.session.returnTo;

          // Redirect to where we came from
          return res.redirect(returnTo);
        });
      });
    })(req, res, next);
  };
};

/**
 * Log errors from oauth2 api endpoints
 */
function errorLogger(err, req, res, next) {
  console.error(err.stack || err);
  next(err);
};

/**
 * Register a plugin that can register multiple callbacks
 */
app.plugin = function(plugin) {
  return plugin(this);
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
  return this;
};

/**
 * Register a callback to issue a token for a given user/client
 *
 * @param {Function} fn
 * @api public
 */

app.issueToken = function(fn) {
  this.callbacks.issueToken = fn;
  return this;
};

/**
 * Register a callback to find a user by ID
 *
 * @param {Function} fn
 * @api public
 */

app.user = function(fn) {
  this.callbacks.user = fn;
  return this;
};

/**
 * Register a callback to find a user by username
 *
 * @param {Function} fn
 * @api public
 */

app.userByUsername = function(fn) {
  this.callbacks.userByUsername = fn;
  return this;
};

/**
 * Register a callback to list a user's allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

app.allowedUserScopes = function(fn) {
  this.callbacks.allowedUserScopes = fn;
  return this;
};

/**
 * Register a callback to verify a user provided password
 *
 * @param {Function} fn
 * @api public
 */

app.verifyPassword = function(fn) {
  this.callbacks.verifyPassword = fn;
  return this;
};

/**
 * Register a callback to lookup a client by clientID
 *
 * @param {Function} fn
 * @api public
 */

app.client = function(fn) {
  this.callbacks.client = fn;
  return this;
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
  return this;
};

/**
 * Register a callback to save an authorization code
 *
 * @param {Function} fn
 * @api public
 */

app.saveAuthorizationCode = function(fn) {
  this.callbacks.saveAuthorizationCode = fn;
  return this;
};

/**
 * Register a callback to invalidate an authorization code
 *
 * @param {Function} fn
 * @api public
 */

app.invalidateAuthorizationCode = function(fn) {
  this.callbacks.invalidateAuthorizationCode = fn;
  return this;
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
  return this;
};

/**
 * Register a callback to render the 'login' page
 *
 * @param {Function} fn
 * @api public
 */

app.loginView = function(fn) {
  this.viewCallbacks.login = fn;
  return this;
};

/**
 * Register a callback to render the 'authorize' page
 *
 * @param {Function} fn
 * @api public
 */

app.authorizeView = function(fn) {
  this.viewCallbacks.authorize = fn;
  return this;
};
