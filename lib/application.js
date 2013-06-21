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
 *
 * @api private
 */

var app = exports = module.exports = {};

/**
 * Initialize the server.
 *
 * @param {Object} opts
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
 * @param {Object} opts
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
 * Log errors from oauth2 api endpoints
 *
 * @param {Error} err
 * @param {Request} req
 * @param {Response} res
 * @param {Function} next
 * @api private
 */

function errorLogger(err, req, res, next) {
  console.error(err.stack || err);
  next(err);
};

/**
 * Get a callback function that has been registered
 *
 * @param {String} name
 * @param {Function} defaultCb
 * @return {Function}
 * @api private
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
 *
 * @param {String} name
 * @param {Function} defaultCb
 * @return {Function}
 * @api private
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
 * `consulate` will ask for a list of scopes to determine if a client's request
 * for a set of scopes is valid. The callback should pass back a list of those
 * valid scopes.
 *
 *     app.scopes(function(done) {
 *       // Possibly make a call to the db or pull from `process.env`
 *       var scopes = process.env.SCOPES.split(',');
 *       done(null, scopes);
 *     });
 *
 * @param {Function} fn
 * @api public
 */

app.scopes = function(fn) {
  debug('registering callback scopes');
  this.callbacks.scopes = fn;
  return this;
};

/**
 * Register a callback to issue a token for a given user/client
 *
 * `consulate` will pass details about an exchange to get an access token
 * in return. The arguments can be used to create encrypted or pseudo-random
 * tokens. If the app chooses a pseudo-random solution it will need to save 
 * the issued token in this step as well.
 *
 *     // encrypted solution
 *     app.issueToken(function(client, user, scope, done) {
 *       // encrypt the `client.id`, `user.id` and `scope` into the token
 *       var token = encrypt(client.id, user.id, scope, Date.now());
 *       // pass the created token back
 *       done(null, token);
 *     });
 *
 *     // pseudo-random solution
 *     app.issueToken(function(client, user, scope, done) {
 *       // hash the `client.id`, `user.id`, `scope`, `Date.now()` and some
 *       // random bytes to get a unique token
 *       var token = hash(client.id, user.id, scope, Date.now());
 *       // save the token to the database
 *       db.saveToken(token, function(err) {
 *         if (err) return done(err);
 *         // pass the created token back
 *         done(null, token);
 *       });
 *     });
 *
 * Check out [consulate-simple-secrets](https://github.com/consulate/consulate-simple-secrets)
 * for an example of the encrypted solution.
 *
 * @param {Function} fn
 * @api public
 */

app.issueToken = function(fn) {
  debug('registering callback issueToken');
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
  debug('registering callback user');
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
  debug('registering callback userByUsername');
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
  debug('registering callback allowedUserScopes');
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
  debug('registering callback verifyPassword');
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
  debug('registering callback client');
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
  debug('registering callback authorizationCode');
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
  debug('registering callback saveAuthorizationCode');
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
  debug('registering callback invalidateAuthorizationCode');
  this.callbacks.invalidateAuthorizationCode = fn;
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

/**
 * Register a plugin that can register multiple callbacks
 *
 * The plugin function will be called with the app as the single argument.
 * The plugin can proceed to register callbacks that the plugin needs.
 *
 *     app.plugin(function(app){
 *       // Register the callbacks here
 *     });
 *
 * A common pattern will include a function that customizes the plugin
 * and returns a closure
 *
 *     function myPlugin (options) {
 *       // maybe set some defaults here
 *       return function(app) {
 *         // Register the callbacks here with options
 *       }
 *     }
 *
 *     app.plugin(myPlugin({
 *       option1: 'foo',
 *       option2: 'bar'
 *     }));
 *
 * Check out some plugins on the [consulate github page](https://github.com/consulate)
 *
 * @param {Function} plugin
 * @api public
 */

app.plugin = function(plugin) {
  return plugin(this);
};

/**
 * Authenticate a user in with the given passport strategy
 *
 * This actually works opposite of the way standard passport `authenticate`.
 * If the user did not authenticate, it will continue on to the next
 * middleware function. If a valid authentication occurred it will redirect to
 * the authorize dialog.
 *
 * @param {String} strategy
 * @param {Function} lookup
 * @return {Strategy} passport strategy
 * @api public
 */

app.authenticate = function(strategy, lookup) {

  // Default to just passing the user through
  lookup = lookup || function(user, fn) { fn(null, user) };

  return function(req, res, next) {
    // We want to do some custom handling here
    debug('authenticating user with strategy '+strategy);
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
