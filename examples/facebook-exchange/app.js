/**
 * Module dependencies
 */
var oauth = require('../..')
  , env = require('envs')
  , db = require('./lib/db')
  , pbkdf2 = require('./lib/pbkdf2')
  , mongo = require('./lib/mongo')
  , facebook = require('./lib/facebook')
  , jade = require('jade');

/**
 * Defines
 */
var SECRETS = env('SECRETS', 'f11c08f4fabb91b70a8fc9f32c88e0d6c6918e0c60e55ddc1d5847d08cb810db').split(',')
  , SCOPES = env('SCOPES', '').split(',');

/**
 * Create an OAuth 2.0 server
 */
var app = module.exports = oauth({session: {
  secret: env('COOKIE_SECRET', 'this is a secret message'),
  key: '_oauth2_session'
}});

/**
 * Configure our app
 */
app
  .set('view engine', 'jade')
  .engine('jade', jade.__express)
  .locals({development: env('NODE_ENV', 'development') === 'development'});

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

app.plugin(facebook({
  getUserByFacebookOrCreate: db.getUserByFacebookOrCreate,
  path: '/auth/facebook',
  clientID: env('FACEBOOK_CLIENT_ID'),
  clientSecret: env('FACEBOOK_CLIENT_SECRET'),
  callbackURL: env('FACEBOOK_CALLBACK_URL', 'http://localhost:5000/auth/facebook')
}));

/**
 * Register a pass hash plugin
 */
app.plugin(pbkdf2({
  salt: env('PASS_SALT', 'i should be at least 64 bits'),
  iterations: env('PASS_ITERATIONS', 64000),
  keylen: env('PASS_KEYLEN', 64)
}));

/**
 * Register the mongo plugin
 */
app.plugin(mongo({
  url: env('MONGO_URL')
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
