"use strict"

// The raw native binding of the running platform, loaded once. Its exports
// are untyped on purpose: index.d.ts describes only the wrapper.

const { loadBinding } = require("../loader.js")

const native = loadBinding()

module.exports = native
