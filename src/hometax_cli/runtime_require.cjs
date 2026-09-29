// Resolve pinned runtime dependencies from the explicit per-user installation.
// Source-development node_modules is a fallback, never an analysis directory.
const {createRequire} = require('node:module');
const {resolve} = require('node:path');
let runtimeRequire = require;
if (process.env.FINANCE_NODE_HOME) {
  runtimeRequire = createRequire(resolve(process.env.FINANCE_NODE_HOME, 'package.json'));
}
module.exports = runtimeRequire;
