const path = require('path');

module.exports = {
  mode: 'production',
  entry: './src/UBE_stage3.js',
  output: {
    filename: 'UBE_stage3_bundle.js',
    path: path.resolve(__dirname, 'dist')
  }
};
