const fs = require("fs");
const path = require("path");

function toHexByte(num) {
  if (typeof num === "string") {
    if (num.startsWith("0x") || num.startsWith("0X")) return num.toLowerCase();
    // try parse decimal string
    const n = parseInt(num, 10);
    return "0x" + (n & 0xff).toString(16).padStart(2, "0");
  }
  return "0x" + (num & 0xff).toString(16).padStart(2, "0");
}

function stringToPaddedHexArray(str, length) {
  if (!str) {
    return Array.from({ length }).map(() => "0x00");
  }
  const bytes = Array.from(str).map(
    (ch) => "0x" + ch.charCodeAt(0).toString(16).padStart(2, "0")
  );
  while (bytes.length < length) bytes.push("0x00");
  return bytes.slice(0, length);
}

/** dateStr expected like "YYMMDDhhmmssZ" or we'll build from ISO date input */
function dateStringToHexArray(dateStr) {
  return stringToPaddedHexArray(dateStr, 16);
}

/** Convert certificate buffer/array to array of hex strings, padded to 512 */
function certificateToHexArray(certInput) {
  let arr = [];
  if (Buffer.isBuffer(certInput)) {
    arr = Array.from(certInput).map((b) => toHexByte(b));
  } else if (Array.isArray(certInput)) {
    // allow mix of numbers or hex strings
    arr = certInput.map((x) =>
      typeof x === "number" ? toHexByte(x) : x.toLowerCase()
    );
  } else {
    throw new Error("certificateToHexArray expects Buffer or Array");
  }

  if (arr.length > 512) {
    // truncate (rare)
    arr = arr.slice(0, 512);
  } else {
    while (arr.length < 512) arr.push("0x00");
  }
  return arr;
}

function generateProverTomlContent(
  certHexArray,
  rdnString,
  checkRdn,
  checkValidity,
  dateStr
) {
  const rdnHex = stringToPaddedHexArray(rdnString, 64);
  const dateHex = dateStringToHexArray(dateStr);
  const certHex = certificateToHexArray(certHexArray);

  const lines = [
    `certificate_bytes = [${certHex.join(", ")}]`,
    `check_rdn = ${checkRdn ? "1" : "0"}`,
    `check_validity = ${checkValidity ? "1" : "0"}`,
    `rdn_first_attribute = [${rdnHex.join(", ")}]`,
    `user_date = [${dateHex.join(", ")}]`,
  ];
  return lines.join("\n");
}

function writeProverToml(dir, content, filename = "Prover.toml") {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const p = path.join(dir, filename);
  fs.writeFileSync(p, content, "utf8");
  return p;
}

module.exports = {
  toHexByte,
  stringToPaddedHexArray,
  dateStringToHexArray,
  certificateToHexArray,
  generateProverTomlContent,
  writeProverToml,
};
