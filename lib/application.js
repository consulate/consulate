/**
 * Module dependencies.
 */

var debug = require('simple-debug')('consulate:application');
var express = require('express');
var envs = require('envs');
var Passport = require('passport').Passport;
var login = require('connect-ensure-login');
var oauth2server = require('./auth/server');
var registerGrants = require('./auth/grants');
var registerExchanges = require('./auth/exchanges');
var clientAuth = require('./auth/client');
var userAuth = require('./auth/user');

// Defines

var NODE_ENV = envs('NODE_ENV', 'production');

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
  var self = this;
  var callbacks = self.callback.bind(self);

  // Check options
  if (!opts.session) throw new Error('Missing `session` options');
  opts.session.key = opts.session.key || '_oauth2_session';

  // default settings
  self.disable('x-powered-by');

  // Initialize our own instance of passport
  var passport = self._passport = new Passport();

  // Setup our oauth modules
  var oauth2 = self._server = oauth2server(callbacks);
  var grants = registerGrants(oauth2, callbacks);
  var exchanges = registerExchanges(oauth2, callbacks);
  var verifyClient = clientAuth(passport, callbacks);
  var user = userAuth(passport, callbacks);

  // Add our middleware
  self
    .use(express.json())
    .use(express.urlencoded())
    .use(express.cookieParser())
    .use(express.cookieSession(opts.session))
    .use(passport.initialize())
    .use(passport.session())
    .use(self.router);

  // Configure the paths
  var paths = opts.paths || {};
  var tokenPath = paths.token || '/token';
  var loginPath = paths.login || '/login';
  var authorizePath = paths.authorize || '/authorize';
  var decisionPath = paths.decision || authorizePath + '/decision';

  // Expose the paths to the views
  self.locals({
    tokenPath: tokenPath,
    loginPath: loginPath,
    authorizePath: authorizePath,
    decisionPath: decisionPath
  });

  // API
  self
    .post(tokenPath, verifyClient(), oauth2.token(), errorLogger, oauth2.errorHandler());

  // UI
  self
    .get(loginPath, self.viewCallback('login'))
    .post(loginPath, self.authenticate(user), self.viewCallback('login'));

  var decision = oauth2.decision();
  var transactionLoader = decision[0];

  self
    .get(authorizePath, login.ensureLoggedIn(), oauth2.authorizeClient(), oauth2.authorizeLocals(), oauth2.getPreviousDecision(), decision)
    .get(authorizePath, self.viewCallback('authorize'))
    .post(decisionPath, login.ensureLoggedIn(), transactionLoader, oauth2.rememberDecision(), decision);
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
  if (NODE_ENV !== 'test') console.error(err.stack || err);
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
    debug('calling callback', name);

    var _args = arguments;

    var done = _args[_args.length - 1];

    var stack = self.callbacks[name] || [defaultCb];
    (function pass(i) {
      var layer = stack[i];
      if (!layer) return done(new Error("'" + name + "' callback not implemented"));

      // Check the arity to see if it accepts a req object
      var args = _args.length === layer.length
        ? Array.prototype.slice.call(_args, 0)
        : Array.prototype.slice.call(_args, 1);

      // Replace the `done` argument with `pass`
      args[args.length - 1] = function(err, obj) {
        if (err === 'pass') return pass(i + 1);
        if (err) return done(err);

        done.apply(null, arguments);
      };

      try {
        layer.apply(null, args);
      } catch(e) {
        return done(e);
      }
    })(0);
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
    debug('calling view callback', name);
    var cb = self.viewCallbacks[name] || defaultCb;
    if (cb) return cb.apply(null, arguments);

    // Pass an error to the provided callback
    var done = arguments[arguments.length - 1];
    done(new Error("'" + name + "' callback not implemented"));
  };
};

/**
 * Register a callback for the allowed scopes
 *
 * `consulate` will ask for a list of scopes to determine if a client's request
 * for a set of scopes is valid. The callback should pass back a list of those
 * valid scopes.
 *
 *     app.getScopes(function(done) {
 *       // Possibly make a call to the db or pull from `process.env`
 *       var scopes = process.env.SCOPES.split(',');
 *       done(null, scopes);
 *     });
 *
 * @param {Function} fn
 * @api public
 */

app.getScopes = function(fn) {
  debug('registering callback getScopes');
  this.addCallback('getScopes', fn);
  return this;
};
backward(app, 'scopes', 'getScopes');

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
  this.addCallback('issueToken', fn);
  return this;
};

/**
 * Register a callback to find a user by ID
 *
 * @param {Function} fn
 * @api public
 */

app.getUser = function(fn) {
  debug('registering callback getUser');
  this.addCallback('getUser', fn);
  return this;
};
backward(app, 'user', 'getUser');

/**
 * Register a callback to find a user by username
 *
 * @param {Function} fn
 * @api public
 */

app.getUserByUsername = function(fn) {
  debug('registering callback getUserByUsername');
  this.addCallback('getUserByUsername', fn);
  return this;
};
backward(app, 'userByUsername', 'getUserByUsername');

/**
 * Register a callback to list a user's allowed scopes
 *
 * @param {Function} fn
 * @api public
 */

app.getAllowedUserScopes = function(fn) {
  debug('registering callback getAllowedUserScopes');
  this.addCallback('getAllowedUserScopes', fn);
  return this;
};
backward(app, 'allowedUserScopes', 'getAllowedUserScopes');

/**
 * Register a callback to verify a user provided password
 *
 * @param {Function} fn
 * @api public
 */

app.verifyPassword = function(fn) {
  debug('registering callback verifyPassword');
  this.addCallback('verifyPassword', fn);
  return this;
};

/**
 * Register a callback to lookup a client by clientID
 *
 * @param {Function} fn
 * @api public
 */

app.getClient = function(fn) {
  debug('registering callback getClient');
  this.addCallback('getClient', fn);
  return this;
};
backward(app, 'client', 'getClient');

/**
 * Register a callback to verify that a client may use the provided uri as the redirect_uri
 *
 * @param {Function} fn
 * @api public
 */

app.verifyClientRedirectURI = function(fn) {
  debug('registering callback verifyClientRedirectURI');
  this.addCallback('verifyClientRedirectURI', fn);
  return this;
};
backward(app, 'isValidClientRedirectURI', 'verifyClientRedirectURI');

/**
 * Register a callback to get a user's previous authorization decision
 *
 * @param {Function} fn
 * @api public
 */

app.getUserDecision = function(fn) {
  debug('registering callback getUserDecision');
  this.addCallback('getUserDecision', fn);
  return this;
};
backward(app, 'userDecision', 'getUserDecision');

/**
 * Register a callback to save a user's authorization decision
 *
 * @param {Function} fn
 * @api public
 */

app.saveUserDecision = function(fn) {
  debug('registering callback saveUserDecision');
  this.addCallback('saveUserDecision', fn);
  return this;
};

/**
 * Register a callback to lookup an authorization code with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

app.getAuthorizationCode = function(fn) {
  debug('registering callback getAuthorizationCode');
  this.addCallback('getAuthorizationCode', fn);
  return this;
};
backward(app, 'authorizationCode', 'getAuthorizationCode');

/**
 * Register a callback to create and save an authorization code
 *
 * @param {Function} fn
 * @api public
 */

app.createAuthorizationCode = function(fn) {
  debug('registering callback createAuthorizationCode');
  this.addCallback('createAuthorizationCode', fn);
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
  this.addCallback('invalidateAuthorizationCode', fn);
  return this;
};

/**
 * Register a callback to lookup a refresh token with its
 * associated information
 *
 * @param {Function} fn
 * @api public
 */

app.getRefreshToken = function(fn) {
  debug('registering callback getRefreshToken');
  this.addCallback('getRefreshToken', fn);
  return this;
};
backward(app, 'refreshToken', 'getRefreshToken');

/**
 * Register a callback to issue a refresh token for a given user/client
 *
 * @param {Function} fn
 * @api public
 */

app.createRefreshToken = function(fn) {
  debug('registering callback createRefreshToken');
  this.addCallback('createRefreshToken', fn);
  return this;
};

/**
 * Register a callback to invalidate a refresh token
 *
 * @param {Function} fn
 * @api public
 */

app.invalidateRefreshToken = function(fn) {
  debug('registering callback invalidateRefreshToken');
  this.addCallback('invalidateRefreshToken', fn);
  return this;
};

/**
 * Get any additional parameters to the response
 *
 * @param {Function} fn
 * @api public
 */

app.getAdditionalParams = function(fn) {
  debug('registering callback getAdditionalParams');
  this.addCallback('getAdditionalParams', fn);
  return this;
};
backward(app, 'additionalParams', 'getAdditionalParams');

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
 * Add callback
 *
 * @param {String} name
 * @param {Function} fn
 * @api private
 */

app.addCallback = function(name, fn) {
  if (this.callbacks[name]) return this.callbacks[name].push(fn);
  this.callbacks[name] = [fn];
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
 * Register a strategy
 *
 * @param {PassportStrategy} strategy
 * @api public
 */

app.register = function(name, strategy) {
  return this._passport.use(name, strategy);
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
 * @param {Object} opts
 * @return {Strategy} passport strategy
 * @api public
 */

app.authenticate = function(strategy, opts) {
  opts = opts || {};
  var self = this;

  return function(req, res, next) {
    // We want to do some custom handling here
    debug('authenticating user with strategy', strategy);
    self._passport.authenticate(strategy, opts, function(err, user, info) {
      debug('authenticated user with strategy', strategy, user, info);
      if (err) return next(err);

      // We couldn't find the user or the password was invalid
      if (!user) {
        res.locals({loginInfo: info || 'Invalid username/password'});
        return next();
      }

      req.logIn(user, function(err) {
        if (err) return next(err);

        var returnTo = req.session.returnTo || res.locals.authorizePath || self.locals.authorizePath;
        // Delete it
        delete req.session.returnTo;

        // Redirect to where we came from
        debug('user logged in; redirecting to', returnTo);
        return res.redirect(returnTo);
      });
    })(req, res, next);
  };
};

/**
 * Register a grant
 *
 * @param {String|Object} type
 * @param {String} phase
 * @param {Function} fn
 * @return {Server} for chaining
 * @api public
 */

app.grant = function(type, phase, fn) {
  this._server.grant(type, phase, fn);
  return this;
};


/**
 * Register an exchange
 *
 * @param {String|Function} type
 * @param {Function} fn
 * @return {Server} for chaining
 * @api public
 */

app.exchange = function(type, fn) {
  this._server.exchange(type, fn);
  return this;
};

/**
 * Backward compatible helper
 *
 * @api private
 */

function backward(app, old, current) {
  app[old] = function(fn) {
    console.warn('***WARNING***', old, 'has been deprecated in favor of', current);
    return this[current](fn);
  };
}
