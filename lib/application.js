/**
 * Module dependencies.
 */

var debug = require('debug')('consulate:application')
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
  if (!opts.session) throw new Error('Missing `session` options');

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
    debug('authenticating user with strategy '+strategy);
    // We want to do some custom handling here
    passport.authenticate(strategy, function(err, foreignUser, info) {
      debug('authenticated user with strategy '+strategy, foreignUser, info);
      if (err) return next(err);

      // We couldn't find the user or the password was invalid
      if (!foreignUser) {
        res.locals({loginInfo: info || 'Invalid username/password'});
        return next();
      }

      debug('looking up user in system', foreignUser);
      lookup(foreignUser, function(err, user) {
        debug('found user in system', user);
        req.logIn(user, function(err) {
          if (err) return next(err);

          var returnTo = req.session.returnTo || '/authorize';
          // Delete it
          delete req.session.returnTo;

          // Redirect to where we came from
          debug('user logged in; redirecting to '+returnTo);
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
app.callback = function(name, defaultCb) {
  var self = this;

  // Create a proxy function so we can return a callback
  // before it's actually defined
  return function() {
    debug('calling callback `'+name+'`');
    if (self.callbacks[name]) return self.callbacks[name].apply(null, arguments);
    if (defaultCb) return defaultCb.apply(null, arguments);
    throw new Error("'"+name+"' callback not found");
  };
};

/**
 * Get a callback function that has been registered
 */
app.viewCallback = function(name, defaultCb) {
  var self = this;

  // Create a proxy function so we can return a callback
  // before it's actually defined
  return function() {
    debug('calling view callback `'+name+'`');
    if (self.viewCallbacks[name]) return self.viewCallbacks[name].apply(null, arguments);
    if (defaultCb) return defaultCb.apply(null, arguments);
    throw new Error("'"+name+"' callback not found");
  };
};

/**
 * Register a callback for the allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('scopes', app);

/**
 * Register a callback to issue a token for a given user/client
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('issueToken', app);

/**
 * Register a callback to find a user by ID
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('user', app);

/**
 * Register a callback to find a user by username
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('userByUsername', app);

/**
 * Register a callback to list a user's allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('allowedUserScopes', app);

/**
 * Register a callback to verify a user provided password
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('verifyPassword', app);

/**
 * Register a callback to lookup a client by clientID
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('client', app);

/**
 * Register a callback to lookup an authorization code with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('authorizationCode', app);

/**
 * Register a callback to save an authorization code
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('saveAuthorizationCode', app);

/**
 * Register a callback to invalidate an authorization code
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('invalidateAuthorizationCode', app);

/**
 * Register a callback to lookup an access token with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

callbackSetter('accessToken', app);

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

/**
 * Helper to create a callback setter
 *
 * @api private
 */
function callbackSetter(name, app) {
  app[name] = function(fn) {
    debug('registering callback '+name);
    this.callbacks[name] = fn;
    return this;
  };
};
