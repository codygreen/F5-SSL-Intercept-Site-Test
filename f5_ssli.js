/*
 * Library to test F5 SSLi site issues
 *
 * This tool will help F5 SSLi and SSLO administrators test
 * websites that are not working.  It will check for common
 * issues with TLS cipher suites and certificate chain trusts
 *
 */

var fs = require('fs');
var https = require('https');
var exports = module.exports = {};
var default_ca_bundle = fs.readFileSync('blended-bundle.crt');
var mod_ca_bundle = fs.readFileSync('mod-blended-bundle.crt');
var default_tmos = "12";


/** 
 * Make an HTTPS connection
 *
 * @constructor 
 * @param {String} hostname
 * @param {Number} port
 * @param {String} suites
 */
exports.httpsReq = function(hostname, port, suites, ca_bundle, callback) {
	// validate function attributes 
	callback = (typeof callback === 'function') ? callback : function() {};
	if (hostname.includes("/")) {
		callback(Error('Not a valid hostname'), null);
	}

	var options = {
	hostname: hostname,
	port: port,
	path: '/',
	method: 'GET',
	ca: ca_bundle,
	ciphers: suites
	};

	var req = https.request(options, function(res) {
		callback(null, res);
	});
	req.on('error', function(e) {
		if (e.message == "unable to get issuer certificate") {
			//console.log("Cert Error: " + e.message);
			callback(Error('Unable to verify certificate trust: ' + e.message), null);	
		} else if (e.message.indexOf("alert handshake failure") > -1) {
			//console.log("Cipher Suite Error: " + e.message);
			callback(Error('Unable to negotiate a TLS cipher suite: ' + e.message), null);	
		} else {
			//console.log("General error" + e.message);
			callback(Error('General error: ' + e.message), null);	
		}
	});
	req.end();
};

/**
 * check CA Bundle
 *
 * @constructor 
 * @param {String} hostname 
 * @param {Number} port
 * @param {String} cipherSuite
 * @param {String} bundle - CA bundle
 */
exports.testCA = function(hostname, port, cipherSuite, bundle, callback) {
	callback = (typeof callback === 'function') ? callback : function() {};

	switch(bundle) {
		case "blended": 
			var ca_bundle = default_ca_bundle;
			break;
		case "empty": 
			var ca_bundle = mod_ca_bundle;
			break;
		default: 
			var ca_bundle = default_ca_bundle;
	}
	exports.httpsReq(hostname, port, cipherSuite, ca_bundle, function(err, res) {
		callback(err, res);
	});
	
}

/**
 * check Cipher Suites
 *
 * @constructor
 * @param {String} hostname
 * @param {Number} port
 * @param {String} cipherSuite
 */
exports.testCiphers = function(hostname, port, cipherSuite, callback) {
	callback = (typeof callback === 'function') ? callback : function() {};
	exports.httpsReq(hostname, port, cipherSuite, default_ca_bundle, function(err, res) {
		callback(err, res);
	});
	
}