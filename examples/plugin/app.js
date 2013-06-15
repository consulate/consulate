/**
 * Module dependencies
 */
var oauth = require('../..')
  , env = require('envs')
  , pbkdf2 = require('./lib/pbkdf2')
  , mongo = require('./lib/mongo')
  , jade = require('jade');

/**
 * Defines
 */
var SECRETS = env('SECRETS', 'f11c08f4fabb91b70a8fc9f32c88e0d6c6918e0c60e55ddc1d5847d08cb810db').split(',')
  , SCOPES = env('SCOPES', '').split(',')
  , COOKIE_SECRET = env('COOKIE_SECRET', 'this is a secret message')
  , PASS_SALT = env('PASS_SALT', 'i should be at least 64 bits')
  , PASS_ITERATIONS = env('PASS_ITERATIONS', 64000)
  , PASS_KEYLEN = env('PASS_KEYLEN', 64)
  , MONGO_URL = env('MONGO_URL')
  , NODE_ENV = env('NODE_ENV', 'development');

/**
 * Create an OAuth 2.0 server
 */
var app = module.exports = oauth({session: {
  secret: COOKIE_SECRET,
  key: '_oauth2_session'
}});

/**
 * Configure our app
 */
app
  .set('view engine', 'jade')
  .engine('jade', jade.__express)
  .locals({development: NODE_ENV === 'development'});

/**
 * Our middleware
 */
app
  .use('/public', oauth.middleware.static(__dirname+'/public'));

/**
 * Error handler
 */
app.use(function errorHandler(err, req, res, next) {
  console.error(err.stack || err.message || err);
  res.status(err.status || 500);
  res.render('error', {err: err});
});

/*****
 * OAuth Plugins
 ****/

/**
 * Register a pass hash plugin
 */
app.plugin(pbkdf2({
  salt: PASS_SALT,
  iterations: PASS_ITERATIONS,
  keylen: PASS_KEYLEN
}));

/**
 * Register the mongo plugin
 */
app.plugin(mongo({
  url: MONGO_URL
}));

/**
 * Expose the allowed scopes
 */
app.scopes(function(done) {
  done(null, SCOPES);
});

/**
 * Expose the secrets
 */
app.secrets(function(done) {
  done(null, SECRETS);
});

/******
 * Views
 ******/

/**
 * Render the 'login' page
 *
 * `locals` is populated with the following values
 *
 * loginInfo: infomation about a login (invalid username/password, etc)
 */
app.loginView(function(req, res) {
  res.render('login');
});

/**
 * Render the 'authorize' page
 *
 * `locals` is populated with the following values
 *
 * action: the action property of the submit form to approve/cancel the authorization
 * user: the current user
 * oauthClient: the client requesting authorization
 * transaction: the id of the oauth 2.0 transaction - this MUST be submitted with the form
 * scopes: an array of scopes which an application is requesting to be approved
 * optionalScopes: an array of optional scopes
 */
app.authorizeView(function(req, res) {
  res.render('authorize');
});
