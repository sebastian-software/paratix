"use strict"

// Internal panic probe (undocumented API). Each kind panics at a different
// kind of native entry point; every one must end as INTERNAL with the fixed
// message, silently, without aborting the process.

const { callNative, callNativeSync, createError } = require("./errors.js")
const { ExecChannelImpl } = require("./exec.js")
const native = require("./native.js")

const PROBE_KINDS = Object.freeze(["sync", "convert", "async", "event", "execReader", "handler"])

/** @returns the error for a probe that unexpectedly returned */
function noPanic() {
  return createError("PROTOCOL", "the panic probe did not panic")
}

function inert() {
  // The probe channel has no native side.
}

async function inertAsync() {
  // The probe channel has no native side.
}

/** @returns an exec channel without a native side, fed by the probe */
function probeChannel() {
  const channel = new ExecChannelImpl({
    ack: inert,
    cancel: inert,
    close: inertAsync,
    end: inertAsync,
    write: inertAsync,
  })
  channel.attach(null)
  return channel
}

/**
 * @param exit the exit of a probe channel
 * @returns rejects with the channel's error
 */
async function expectRejection(exit) {
  await exit
  throw noPanic()
}

/**
 * Panics at one kind of native entry point.
 *
 * @param kind `sync`, `convert`, `async`, `event`, `execReader` or `handler`
 * @returns rejects with INTERNAL (`sync`/`convert` throw instead)
 */
function internalPanicProbe(kind) {
  switch (kind) {
    case "event": {
      const channel = probeChannel()
      callNativeSync(() => native.panicProbeEvent(channel.handleEvent))
      return expectRejection(channel.exit)
    }
    case "execReader": {
      const channel = probeChannel()
      return callNative(() => native.panicProbeExecReader(channel.handleEvent)).then(() =>
        expectRejection(channel.exit)
      )
    }
    case "handler": {
      return callNative(() => native.panicProbeHandler())
    }
    case "sync": {
      callNativeSync(() => native.panicProbeSync())
      throw noPanic()
    }
    case "convert": {
      callNativeSync(() => native.panicProbeConvert({}))
      throw noPanic()
    }
    case "async": {
      return callNative(() => native.panicProbeAsync())
    }
    default: {
      throw new TypeError(`unknown probe kind; expected one of ${PROBE_KINDS.join(", ")}`)
    }
  }
}

module.exports = { internalPanicProbe }
