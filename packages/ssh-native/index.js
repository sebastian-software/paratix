"use strict"

// @paratix/ssh-native: the public API. See index.d.ts and README.md.

const { connect } = require("./lib/connect.js")
const { callNativeSync } = require("./lib/errors.js")
const native = require("./lib/native.js")
const { internalPanicProbe } = require("./lib/probe.js")
const { scan } = require("./lib/session.js")
const { currentTarget, SUPPORTED_TARGETS } = require("./loader.js")

/** @returns name of the crypto backend compiled into the binary (`aws-lc-rs`) */
function cryptoBackend() {
  return callNativeSync(() => native.cryptoBackend())
}

module.exports = {
  __internalPanicProbe: internalPanicProbe,
  connect,
  cryptoBackend,
  currentTarget,
  scan,
  SUPPORTED_TARGETS,
}
