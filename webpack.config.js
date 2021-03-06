var path = require('path');
var webpack = require('webpack');

module.exports = {
	entry: {
		rsa: path.resolve('src/NodeRSA.browser.js')
	},
	output: {
		path: 'dist/',
		filename: '[name].js',
		library: 'NodeRSA',
		libraryTarget: 'umd',
		// pathinfo: true
	},

	module: {
		loaders: [{
			test: /\.js$/,
			loader: 'es3ify'
		}, {
			test: /\.js$/,
			loader: 'babel',
			query: {
				presets: ['es2015-loose']
			}
		}, {
			test: /\.json$/,
			loader: 'json'
		}]
	},

	resolve: {
		alias: {
			'crypto': __dirname + '/src/libs/crypto.browser.js'
		}
	},

	plugins: [
		new webpack.optimize.UglifyJsPlugin({
			compress: {
				warnings: false
			}
		}),
	],

	devtool: '#source-map'
};
