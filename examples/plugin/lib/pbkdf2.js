/**
 * Module dependencies
 */
var pbkdf2 = require("crypto").pbkdf2;

module.exports = function(options) {
  return function(app) {
    app.hashPassword(function(password, user, done) {
      pbkdf2(password, options.salt, options.iterations, options.keylen, function(err, hash) {
        if (err) return done(err);
        done(null, hash.toString('hex'));
      });
    });
  };
};