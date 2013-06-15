/**
 * Module dependencies
 */
var oauth = require("..")
  , env = require("envs")
  , pbkdf2 = require("crypto").pbkdf2
  , db = require("./lib/db");

/**
 * Defines
 */
var SECRETS = env("SECRETS", "").split(',')
  , SCOPES = env("SCOPES", "").split(',')
  , PASS_SALT = env("PASS_SALT", "i should be at least 64 bits")
  , PASS_ITERATIONS = env("PASS_ITERATIONS", 64000)
  , PASS_KEYLEN = env("PASS_KEYLEN", 64);

/**
 * Create an OAuth 2.0 server
 */
var app = module.exports = oauth();

/**
 * Configure our app
 */
app
  .set("view engine", "jade")
  .engine("jade", require("jade").__express)
  .use("/public", oauth.middleware.static(__dirname+"/public"));

/*****
 * Generic callbacks
 ****/

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


/*****
 * User callbacks
 ****/

/**
 * Lookup a user
 */
app.user(function(userID, done) {
  // Get the info from a db, file, env, etc
  db.getUser(userID, function(err, user) {
    // The user needs to have the following properties:
    // {
    //   passhash: "..."
    // }

    done(err, user);
  });
});

/**
 * List the scopes the user is allowed
 */
app.allowedUserScopes(function(user, done) {
  // TODO Pull the result from the db
  done(null, user.scopes || []);
});

/**
 * Hash a user provided password
 */
app.hashPassword(function(password, user, done) {
  pbkdf2(password, PASS_SALT, PASS_ITERATIONS, PASS_KEYLEN, done);
});


/*****
 * Client callbacks
 ****/

/**
 * Look up a client
 */
app.client(function(clientID, done) {
  // Get the info from a db, file, env, etc
  db.getClient(clientID, function(err, client) {
    // The client needs to have the following properties:
    // {
    //   secret: "...",
    //   callbacks: ["...", "..."],
    //   scopes: ["...", "..."],
    //   optional_scopes: ["...", "..."]
    // }

    done(err, client);
  });
});


/*****
 * Authorization code callbacks
 ****/

app.authorizationCode(function(code, done) {
  // Get the info from a db, file, env, etc
  db.getAuthorizationCode(code, function(err, authCode) {
    // The authCode needs to have the following properties:
    // {
    //   client_id: "...",
    //   user_id: "...",
    //   redirect_uri: "..."
    // }

    done(err, authCode);
  });
});

app.saveAuthorizationCode(function(code, userID, clientID, redirectURI, done) {
  // Save the info from a db, file, env, etc
  db.saveAuthorizationCode(code, userID, clientID, redirectURI, done);
});

/*****
 * Access token callbacks
 ****/

app.accessToken(function(token, done) {
  // Get the info from a db, file, env, etc
  db.getAccessToken(token, function(err, accessToken) {
    // The accessToken needs to have the following properties:
    // {
    //   client_id: "...",
    //   user_id: ["...", "..."]
    // }

    done(err, accessToken);
  });
});

app.saveAccessToken(function(code, userID, clientID, done) {
  // Save the info from a db, file, env, etc
  db.saveAccessToken(code, userID, clientID, done);
});

/******
 * Views
 ******/

/**
 * Render the 'login' page
 *
 * `locals` is populated with the following values
 *
 * submitURL: url at which to POST the login form data
 * loginError: infomation about a login error (invalid username/password)
 */
app.loginView(function(req, res) {
  res.render("login");
});

/**
 * Render the 'authorize' page
 *
 * `locals` is populated with the following values
 *
 * submitURL: url at which to POST the approval information
 * scopes: an array of scopes which an application is requesting to be approved
 * optionalScopes: an array of optional scopes
 * clientName: the name of the requesting client
 * clientDescription: a brief description of the requesting client
 * clientImage: a small image/logo of the requesting client
 */
app.authorizeView(function(req, res) {
  res.render("authorize");
});
