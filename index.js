module.exports = process.env.CONSULATE_COV
  ? require('./lib-cov')
  : require('./lib');
