"use strict";

/* Key pairs are generated in this browser and the private half never leaves
   this machine.

   aws/key_pairs.py refuses to call CreateKeyPair because that API returns the
   private key in the response body, which puts a secret somewhere it can be
   logged, cached, proxied or captured in a crash dump. Having the server
   generate one and send it down here would recreate exactly that, with more
   hops. The IAM policy denies ec2:CreateKeyPair outright, so it could not
   happen even by accident.

   So the work moves to where the secret already is. WebCrypto makes the pair,
   the private half is written straight to a download, and the only thing that
   reaches the API is the public half - which is what ImportKeyPair takes and
   what AWS stores. There is no secret in flight because there is no secret to
   put in flight.

   crypto.subtle requires a secure context. http://127.0.0.1 counts as one, so
   this works on the localhost binding the backend uses; it would not work if
   the API were moved to a plain-HTTP LAN address, which it should not be.

   The byte layouts below are the OpenSSH wire format (RFC 4253 §6.6 for the
   public blob, and the openssh-key-v1 container for the private file). Both
   were verified against ssh-keygen before this shipped. */

const KeyGen = (() => {
  const enc = new TextEncoder();

  function bytes(...parts) {
    let total = 0;
    for (const p of parts) total += p.length;
    const out = new Uint8Array(total);
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
  }

  function u32(n) {
    return new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255,
                           (n >>> 8) & 255, n & 255]);
  }

  // An SSH "string": a 32-bit big-endian length, then that many bytes.
  function sshString(data) {
    const raw = typeof data === "string" ? enc.encode(data) : data;
    return bytes(u32(raw.length), raw);
  }

  // An SSH "mpint": a signed big-endian integer. A leading zero byte is
  // required when the top bit is set, or the value reads as negative.
  function sshMpint(raw) {
    let i = 0;
    while (i < raw.length - 1 && raw[i] === 0) i++;
    const trimmed = raw.subarray(i);
    return (trimmed[0] & 0x80)
      ? sshString(bytes(new Uint8Array([0]), trimmed))
      : sshString(trimmed);
  }

  function b64(data) {
    let s = "";
    for (const b of data) s += String.fromCharCode(b);
    return btoa(s);
  }

  function fromB64Url(s) {
    const std = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (4 - (std.length % 4)) % 4;
    const bin = atob(std + "=".repeat(pad));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function pem(label, data) {
    const body = b64(data).replace(/(.{70})/g, "$1\n").replace(/\n$/, "");
    return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
  }

  /* The openssh-key-v1 container, unencrypted.

     magic "openssh-key-v1\0", cipher "none", kdf "none", empty kdfoptions,
     one key, the public blob, then a private section padded to a multiple of
     the cipher block size with the bytes 1, 2, 3… The two check integers must
     match; ssh-keygen uses them to tell a wrong passphrase from a good one,
     and they are simply equal here because nothing is encrypted. */
  function opensshPrivateFile(publicBlob, privateFields, comment) {
    const check = crypto.getRandomValues(new Uint32Array(1))[0];

    let section = bytes(u32(check), u32(check), ...privateFields,
                        sshString(comment));

    const padTo = 8;
    const padding = new Uint8Array((padTo - (section.length % padTo)) % padTo);
    for (let i = 0; i < padding.length; i++) padding[i] = i + 1;
    section = bytes(section, padding);

    return pem("OPENSSH PRIVATE KEY", bytes(
      enc.encode("openssh-key-v1"), new Uint8Array([0]),
      sshString("none"),
      sshString("none"),
      sshString(""),
      u32(1),
      sshString(publicBlob),
      sshString(section),
    ));
  }

  async function ed25519(comment) {
    const pair = await crypto.subtle.generateKey(
      { name: "Ed25519" }, true, ["sign", "verify"]);

    const pub = new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey));

    // PKCS#8 for Ed25519 is a fixed 48 bytes: a 16-byte header then the
    // 32-byte seed. OpenSSH stores seed||public as the private field.
    const pkcs8 = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const seed = pkcs8.slice(pkcs8.length - 32);

    const publicBlob = bytes(sshString("ssh-ed25519"), sshString(pub));

    return {
      type: "ED25519",
      publicKey: `ssh-ed25519 ${b64(publicBlob)} ${comment}`,
      privateKey: opensshPrivateFile(publicBlob, [
        sshString("ssh-ed25519"),
        sshString(pub),
        sshString(bytes(seed, pub)),
      ], comment),
      filename: "id_ed25519",
    };
  }

  async function rsa(comment) {
    const pair = await crypto.subtle.generateKey({
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 3072,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    }, true, ["sign", "verify"]);

    const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
    const publicBlob = bytes(
      sshString("ssh-rsa"),
      sshMpint(fromB64Url(jwk.e)),
      sshMpint(fromB64Url(jwk.n)),
    );

    // PKCS#8 rather than the openssh container. OpenSSH reads PKCS#8 for RSA
    // directly, so the simpler encoding is also the correct one here.
    const pkcs8 = new Uint8Array(
      await crypto.subtle.exportKey("pkcs8", pair.privateKey));

    return {
      type: "RSA",
      publicKey: `ssh-rsa ${b64(publicBlob)} ${comment}`,
      privateKey: pem("PRIVATE KEY", pkcs8),
      filename: "id_rsa",
    };
  }

  /* Ed25519 where the browser has it, RSA otherwise.

     Ed25519 is shorter, faster and at least as strong, and it is what the
     tool recommends - importing an RSA key produces an advisory finding
     saying so. But WebCrypto only gained Ed25519 recently, and a form that
     fails on an older browser is worse than one that makes a 3072-bit RSA
     key and says what it did. */
  async function generate(comment) {
    try {
      return await ed25519(comment);
    } catch (e) {
      const pair = await rsa(comment);
      pair.note = "This browser cannot generate ED25519 keys, so an RSA key " +
                  "was made instead. It works; the tool will note that " +
                  "ED25519 would be preferable.";
      return pair;
    }
  }

  return { generate };
})();
