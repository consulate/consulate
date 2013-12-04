/**
 * Module dependencies
 */

var expect = require('expect.js');
var consulate = require('..');

describe('consulate application', function() {
  var app;

  beforeEach(function() {
    app = consulate({session: {
      secret: 'consulate'
    }});
  });

  it('should allow registering a plugin', function() {
    app.plugin(function(pluginApp) {
      expect(pluginApp).to.be(app);
    });
  });

  it('should throw an exception when a callback is not found and is called', function() {
    var notFound = app.callback('non-existant-callback');
    notFound(function(err) {
      expect(err).to.be.ok();
    });
  });

  it('should throw an exception when a view callback is not found and is called', function() {
    var notFound = app.viewCallback('non-existant-view-callback');
    notFound(function(err) {
      expect(err).to.be.ok();
    });
  });

  it('should register alternative grant types', function() {
    app.grant(function() {});
  });

  it('should register alternative exchange types', function() {
    app.exchange(function() {});
  });

  it('should register passport strategies', function() {
    app.register('testing', function() {});
  });
});
