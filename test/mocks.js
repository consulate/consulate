function MockRequest() {
}

function MockResponse() {
  this._headers = {};
  this._data = '';
}

MockResponse.prototype.setHeader = function(name, value) {
  this._headers[name] = value;
}

MockResponse.prototype.redirect = function(location) {
  this._redirect = location;
  this.end();
}

MockResponse.prototype.end = function(data, encoding) {
  this._data += data;
  if (this.done) { this.done(); }
}

exports.MockRequest  = MockRequest;
exports.MockResponse = MockResponse;
