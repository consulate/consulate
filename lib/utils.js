/**
 * Merge object b with object a.
 *
 *     var a = { foo: 'bar' }
 *       , b = { bar: 'baz' };
 *
 *     utils.merge(a, b);
 *     // => { foo: 'bar', bar: 'baz' }
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object}
 * @api private
 */

exports.merge = function(a, b){
  if (a && b) {
    for (var key in b) {
      a[key] = b[key];
    }
  }
  return a;
};

exports.clientScopesNoop = function(scope) {
  return function(req, client, done) {
    done(null, scope);
  };
};

exports.defaultClientScopes = function(req, client, done) {
  done(null, client.scope || client.scopes);
};

exports.defaultFilterScopesByClient = function(req, client, scope, done) {
  done(null, scope || []);
};

exports.defaultFilterScopesByUser = function(req, user, scope, done) {
  done(null, scope || []);
};
