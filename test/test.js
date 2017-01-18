var expect = require('chai').expect;
var assert = require('chai').assert;
var ssli = require('../f5_ssli');
var fs = require('fs');


var testSite = "f5.com";
var testSitePort = 443;
var testTMOSVersion = 12;
var cipher_suites = JSON.parse(fs.readFileSync('tmos_default_cipher_suites.json', 'utf8'));

describe("F5 SSLi Site Test Suite", function() {
	describe("F5 Library Tests", function() {
		it("Test for valid HTTP hostname", function(done) {
			setTimeout( function() {
				ssli.testCiphers("https://f5.com/", testSitePort, cipher_suites[testTMOSVersion], function(err, data) {
					assert.isDefined(err);
					expect(err).to.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
	})
	describe("F5 TLS Cipher Tests", function() {
		it("Test TLS Ciphers for TMOS 12.0-12.1", function(done) {
			setTimeout( function() {
				ssli.testCiphers(testSite, testSitePort, cipher_suites["12"], function(err, data) {
					assert.isDefined(data);
					expect({data}).to.be.an('object');
					expect(data).to.not.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
		it("Test TLS Ciphers for TMOS 11.6.1", function(done) {
			setTimeout( function() {
				ssli.testCiphers(testSite, testSitePort, cipher_suites["11.6.1"], function(err, data) {
					assert.isDefined(data);
					expect({data}).to.be.an('object');
					expect(data).to.not.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
		it("Test TLS Ciphers for TMOS 11.6.0", function(done) {
			setTimeout( function() {
				ssli.testCiphers(testSite, testSitePort, cipher_suites["11.6.0"], function(err, data) {
					assert.isDefined(data);
					expect({data}).to.be.an('object');
					expect(data).to.not.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
		it("Test TLS Ciphers for TMOS 11.5", function(done) {
			setTimeout( function() {
				ssli.testCiphers(testSite, testSitePort, cipher_suites["11.5"], function(err, data) {
					assert.isDefined(data);
					expect({data}).to.be.an('object');
					expect(data).to.not.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
		it("Test Weak Ciphers", function(done) {
			setTimeout( function() {
				ssli.testCiphers(testSite, testSitePort, cipher_suites["weak"], function(err, data) {
					assert.isDefined(err);
					expect(err).to.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
	})
	describe("F5 Certificate Bundle Tests", function() {
		it("Test Blended Bundle", function(done) {
			setTimeout( function() {
				ssli.testCA(testSite, testSitePort, cipher_suites[testTMOSVersion], "blended", function(err, data) {
					assert.isDefined(data);
					expect({data}).to.be.an('object');
					expect(data).to.not.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
		it("Test Empty Bundle", function(done) {
			setTimeout( function() {
				ssli.testCA(testSite, testSitePort, "empty", function(err, data) {
					assert.isDefined(err);
					expect(err).to.be.an.instanceof(Error);
				});
				done();
			}, 100 );
		})
	})
})