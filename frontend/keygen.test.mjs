/* Runs the real key generator and asks ssh-keygen whether it worked.
 *
 * keygen.js was written and shipped without ever being executed here: there
 * was no JavaScript engine in the development environment, so the OpenSSH
 * byte layouts were checked by writing the same encoder a second time in
 * Python and verifying that one. That proves the algorithm and says nothing
 * about the code that actually runs in a browser.
 *
 * Node has WebCrypto, btoa, atob and TextEncoder as globals, which are the
 * only browser APIs keygen.js touches, so the file runs here unmodified. This
 * generates a pair, writes the private half to disk, and has ssh-keygen
 * derive the public half from it. If the container, the padding, the check
 * integers or the length prefixes are wrong, ssh-keygen refuses the file or
 * derives a different key.
 *
 *     node frontend/keygen.test.mjs
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// keygen.js is a plain script, not a module: it exists to be loaded by a
// <script> tag. Evaluating it and asking for the binding it declares is how
// to reach it without changing the file to suit its test.
function load() {
  const source = readFileSync(join(here, "keygen.js"), "utf8");
  return new Function(`${source}\nreturn KeyGen;`)();
}

let failures = 0;

function check(condition, message) {
  console.log(`  ${condition ? "pass" : "FAIL"}  ${message}`);
  if (!condition) failures += 1;
  return condition;
}

/* Ask ssh-keygen to derive the public half from the private file we wrote.
 * It is the authority here: it is what will actually read this key. */
function derivePublic(privateKey, filename) {
  const dir = mkdtempSync(join(tmpdir(), "scp-keygen-"));
  const path = join(dir, filename);
  try {
    writeFileSync(path, privateKey, { mode: 0o600 });
    return execFileSync("ssh-keygen", ["-y", "-f", path], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

async function verify(label, pair) {
  console.log(`\n${label}`);
  console.log("-".repeat(label.length));

  check(!pair.privateKey.includes(pair.publicKey.split(" ")[1]),
        "the private file does not simply contain the public line");
  // Three fields, but the comment is everything after the second space and
  // this tool's own comment has a space in it: "<name> (secure-cloud-
  // provisioner)". Splitting on every space and counting is how that reads as
  // malformed when it is exactly what ssh-keygen writes.
  const [algorithm, material, ...comment] = pair.publicKey.split(" ");
  check(algorithm.startsWith("ssh-"), "the public half names its algorithm");
  check(/^[A-Za-z0-9+/]+=*$/.test(material),
        "the key itself is base64 and nothing else");
  check(comment.length > 0, "and carries a comment");
  check(/^-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(pair.privateKey),
        "the private half is a PEM block");

  let derived;
  try {
    derived = derivePublic(pair.privateKey, pair.filename);
  } catch (e) {
    check(false, `ssh-keygen could not read the private key: ${e.message}`);
    return;
  }
  check(true, "ssh-keygen parsed the private key");

  const [mineType, mineKey] = pair.publicKey.split(" ");
  const [theirType, theirKey] = derived.split(" ");

  check(mineType === theirType, `the algorithm agrees (${mineType})`);
  check(mineKey === theirKey,
        "ssh-keygen derives exactly the public key we generated");
}

const KeyGen = load();

// The real path, as a current browser takes it.
await verify("ED25519", await KeyGen.generate("smoke (secure-cloud-provisioner)"));

// The fallback, forced by refusing Ed25519 the way an older browser does.
// Worth exercising deliberately: it is the branch nobody developing on a
// current browser will ever reach by accident.
const realGenerateKey = globalThis.crypto.subtle.generateKey.bind(
  globalThis.crypto.subtle);
globalThis.crypto.subtle.generateKey = (algorithm, ...rest) => {
  const name = typeof algorithm === "string" ? algorithm : algorithm.name;
  if (name === "Ed25519") {
    return Promise.reject(new Error("Ed25519 unsupported in this browser"));
  }
  return realGenerateKey(algorithm, ...rest);
};

const fallback = await KeyGen.generate("smoke (secure-cloud-provisioner)");
globalThis.crypto.subtle.generateKey = realGenerateKey;

console.log("\nRSA fallback");
console.log("------------");
check(fallback.type === "RSA",
      "a browser without Ed25519 gets an RSA key rather than an error");
check(Boolean(fallback.note), "and is told why");
await verify("RSA fallback, verified", fallback);

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
