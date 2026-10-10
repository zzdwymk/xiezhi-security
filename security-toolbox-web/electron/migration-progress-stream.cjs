"use strict";
const { StringDecoder } = require("node:string_decoder");

// The Java copier already emits each progress message through its logger as
// "MIGRATE: ...". Reuse the required stdout capture instead of a second append
// file. UI forwarding is bounded even for unusually long error lines.
function observeMigrationProgress(readable, { onProgress, onFault = () => {}, maxFragmentCharacters = 65536 }) {
  if (!Number.isSafeInteger(maxFragmentCharacters) || maxFragmentCharacters < 32) throw new Error("Invalid migration progress fragment limit");
  const decoder = new StringDecoder("utf8"), marker = "MIGRATE: ";
  let buffer = "", forwarding = false, prefixTail = "", stopped = false;
  const consume = (fragment, final) => {
    let text = fragment;
    if (!forwarding) {
      text = prefixTail + text;
      const position = text.indexOf(marker);
      if (position >= 0) { forwarding = true; text = text.slice(position + marker.length); }
      else { prefixTail = text.slice(-(marker.length - 1)); text = ""; }
    }
    if (forwarding && text) {
      try { onProgress(text.replace(/\r$/, "")); } catch (error) { onFault(error); }
    }
    if (final) { forwarding = false; prefixTail = ""; }
  };
  const drain = () => {
    while (buffer.length) {
      const newline = buffer.indexOf("\n");
      if (newline >= 0 && newline <= maxFragmentCharacters) {
        consume(buffer.slice(0, newline), true); buffer = buffer.slice(newline + 1);
      } else if (buffer.length > maxFragmentCharacters) {
        let end = maxFragmentCharacters;
        if (/[\uD800-\uDBFF]/.test(buffer[end - 1])) end--;
        consume(buffer.slice(0, end), false); buffer = buffer.slice(end);
      } else break;
    }
  };
  const data = chunk => { if (!stopped) { buffer += decoder.write(chunk); drain(); } };
  const end = () => {
    if (stopped) return;
    buffer += decoder.end(); drain(); if (buffer) consume(buffer, true); buffer = ""; stop();
  };
  const error = error => { onFault(error); };
  function stop() {
    if (stopped) return; stopped = true;
    readable.off("data", data); readable.off("end", end); readable.off("close", end); readable.off("error", error);
    buffer = "";
  }
  readable.on("data", data); readable.once("end", end); readable.once("close", end); readable.on("error", error);
  return { stop, state: () => ({ stopped, bufferedCharacters: buffer.length, maxFragmentCharacters }) };
}

module.exports = { observeMigrationProgress };
