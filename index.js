module.exports = process.env.AUTH_COV
  ? require('./lib-cov')
  : require('./lib');
