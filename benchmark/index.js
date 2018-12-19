const Benchmark = require('benchmark');
const eccNative = require('../src');
const eccJs = require('eosjs-ecc');
const getRandomBytes = require('crypto').randomBytes;

const suite = new Benchmark.Suite;
const pvt = eccNative.seedPrivate('')
const pubkey = eccNative.privateToPublic(pvt)
// add tests
suite
.add('eosjs-ecc-native#sign', function() {
  const data = getRandomBytes(128);
  const sig = eccNative.sign(data, pvt);
})
.add('eosjs-ecc-js#sign', function() {
  const data = getRandomBytes(128);
  const sig = eccJs.sign(data, pvt);
})
// add listeners
.on('cycle', function(event) {
  console.log(String(event.target));
})
.on('complete', function() {
  console.log('Fastest is ' + this.filter('fastest').map('name'));
})
// run async
.run({ 'async': true });
