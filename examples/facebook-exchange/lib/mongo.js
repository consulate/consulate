/**
 * Module dependencies
 */
var db = require('./db'); // TODO implement mongo connection

module.exports = function(options) {
  return function(app) {
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
        //   id: "...",
        //   passhash: "..."
        // }

        done(err, user);
      });
    });

    /**
     * Lookup a user by username
     */
    app.userByUsername(function(username, done) {
      // Get the info from a db, file, env, etc
      db.getUserByUsername(username, function(err, user) {
        // The user needs to have the following properties:
        // {
        //   id: "...",
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
        //   id: "...",
        //   secret: "...",
        //   redirect_uri: "...", // or ["...", "..."] for multiple
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
  };
};