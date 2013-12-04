/**
 * Module dependencies.
 */

var debug = require('simple-debug')('consulate:auth:server');
var oauth2orize = require('oauth2orize');

exports = module.exports = function(callbacks) {
  var server = oauth2orize();
  var getClient = callbacks('getClient');
  var verifyClientRedirectURI = callbacks('verifyClientRedirectURI');
  var getUserDecision = callbacks('getUserDecision', function(user, client, done) { done(); });
  var saveUserDecision = callbacks('saveUserDecision', function(user, client, decision, done) { done(); });

  // Serialize the client
  server.serializeClient(function(client, done) {
    debug('serializing client', client);
    done(null, client.id);
  });

  // Deserialize the client
  server.deserializeClient(function(req, id, done) {
    debug('deserializing client_id', id);
    getClient(req, id, function(err, client) {
      debug('deserialized client_id', id, client);
      if (err) return done(err);
      return done(null, client);
    });
  });

  // Setup authorize
  server.authorizeClient = function() {
    return server.authorization(function(req, clientID, redirectURI, scope, type, done) {
      debug('getting client', clientID, 'with redirect_uri', redirectURI);
      getClient(req, clientID, function(err, client) {
        debug('got client', clientID, client);
        if (err) return done(err);
        if (!client) return done(null, false);

        verifyClientRedirectURI(req, client, redirectURI, function(err, isValid) {
          if (err) return done(err);
          if (!isValid) return done(null, isValid);
          return done(null, client, redirectURI)
        });

      });
    });
  };

  // Retrieve a previous decision
  server.getPreviousDecision = function() {
    return function(req, res, next) {
      getUserDecision(req, req.user, req.oauth2.client, function(err, decision) {
        if (err) return next(err);
        // If the decision was no, render the view
        if (!decision) return next('route');

        // TODO decision should probably be a list of approved scopes

        // Pass it on to the decision handler
        next();
      });
    };
  };

  // Remeber a user decision
  server.rememberDecision = function() {
    return function(req, res, next) {
      var decision = !req.body.cancel;

      saveUserDecision(req, req.user, req.oauth2.client, decision, function(err) {
        if (err) return next(err);
        next(err);
      });
    };
  };

  // Setup the authorize endpoint locals
  server.authorizeLocals = function() {
    return function(req, res, next) {
      var locals = {
        action: '/authorize/decision', // TODO resolve this so we can be mounted anywhere
        transaction: req.oauth2.transactionID,
        user: req.user,
        oauthClient: req.oauth2.client,
        scopes: req.oauth2.client.scope, // TODO display the ad-hoc scope requests, if any
        optionalScopes: req.oauth2.client.optional_scopes // TODO display the ad-hoc optional scope requests, if any
      };
      debug('setting authorize view locals', locals);
      res.locals(locals);
      next();
    };
  };

  return server;
}
