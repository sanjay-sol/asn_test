// server.js
const express = require("express");
const multer = require("multer");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const {
  generateProverTomlContent,
  writeProverToml,
  certificateToHexArray,
} = require("./helpers/generateToml");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const upload = multer({ storage: multer.memoryStorage() });

// Configure
const PORT = process.env.PORT || 5000;
const CIRCUIT_DIR = process.env.CIRCUIT_DIR || path.join(__dirname, "circuits");
// Expect circuits/target/asn.json present

function maybePemToDer(buffer) {
  const s = buffer.toString("utf8");
  if (s.includes("-----BEGIN")) {
    const body = s
      .replace(/-----BEGIN [^-]+-----/g, "")
      .replace(/-----END [^-]+-----/g, "")
      .replace(/\s+/g, "");
    return Buffer.from(body, "base64");
  }
  return buffer;
}

// Utility to try commands (multiple variants)
function runCommands(variants, cwd, timeoutMs = 120000) {
  for (const v of variants) {
    try {
      console.log(`> ${v.cmd} ${v.args.join(" ")}`);
      const result = spawnSync(v.cmd, v.args, {
        cwd,
        encoding: "utf8",
        stdio: "pipe",
        timeout: timeoutMs,
      });
      if (result.error) {
        console.warn("command error:", result.error.message);
        continue;
      }
      console.log("stdout:", result.stdout ? result.stdout.slice(0, 500) : "");
      console.log("stderr:", result.stderr ? result.stderr.slice(0, 500) : "");
      if (result.status === 0) return { ok: true, result };
      else {
        console.warn(`exit ${result.status}`);
        continue;
      }
    } catch (err) {
      console.warn("spawn threw", err && err.message);
      continue;
    }
  }
  return { ok: false, error: "all commands failed" };
}

/**
 * POST /api/generate-proof
 * fields:
 *  - certFile (file)
 *  - rdnString (string)
 *  - checkRdn ("1"/"0" or "true"/"false")
 *  - checkValidity ("1"/"0" or "true"/"false")
 *  - date (ISO date string e.g. "2025-06-20") OR full YYMMDDhhmmssZ string if provided
 */
app.post("/api/generate-proof", upload.single("certFile"), async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ error: "Missing certFile upload" });

    const rawBuffer = maybePemToDer(req.file.buffer);

    const rdnString = req.body.rdnString || "";
    const checkRdn =
      req.body.checkRdn === "1" ||
      req.body.checkRdn === "true" ||
      req.body.checkRdn === true;
    const checkValidity =
      req.body.checkValidity === "1" ||
      req.body.checkValidity === "true" ||
      req.body.checkValidity === true;
    let dateInput = req.body.dateStr || req.body.date || ""; // allow multiple names

    // If user provided ISO date like "2025-06-20", convert to YYMMDD120000Z
    if (dateInput && !/^\d{2}\d{2}\d{2}\d{6}Z$/.test(dateInput)) {
      // try parse YYYY-MM-DD
      try {
        const d = new Date(dateInput);
        if (!isNaN(d.getTime())) {
          const yy = String(d.getUTCFullYear()).slice(-2).padStart(2, "0");
          const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
          const dd = String(d.getUTCDate()).padStart(2, "0");
          // default time 12:00:00
          dateInput = `${yy}${mm}${dd}120000Z`;
        }
      } catch (e) {
        // leave as-is
      }
    }

    const certHexArray = certificateToHexArray(rawBuffer);

    // Build TOML and write to circuit dir
    const tomlContent = generateProverTomlContent(
      certHexArray,
      rdnString,
      checkRdn,
      checkValidity,
      dateInput
    );
    const tomlPath = writeProverToml(CIRCUIT_DIR, tomlContent, "Prover.toml");

    // 1) run nargo execute (to produce witness target/asn.gz). Try variants.
    const executeVariants = [
      { cmd: "nargo", args: ["execute", "--toml", tomlPath] },
      {
        cmd: "nargo",
        args: ["execute", "--prover", "toml", "--toml", tomlPath],
      },
      // fallback no args - might pick up Prover.toml in cwd if CIRCUIT_DIR
      { cmd: "nargo", args: ["execute"] },
    ];
    let r1 = runCommands(executeVariants, CIRCUIT_DIR, 180000);
    if (!r1.ok) {
      return res
        .status(500)
        .json({ error: "nargo execute failed", details: r1.error || r1 });
    }

    // Expected witness path (most toolings use target/<name>.gz, we will search target for newest .gz)
    const targetDir = path.join(CIRCUIT_DIR, "target");
    let witnessPath = null;
    if (fs.existsSync(targetDir)) {
      const files = fs.readdirSync(targetDir).filter((f) => f.endsWith(".gz"));
      if (files.length > 0) {
        // choose latest by mtime
        files.sort(
          (a, b) =>
            fs.statSync(path.join(targetDir, b)).mtimeMs -
            fs.statSync(path.join(targetDir, a)).mtimeMs
        );
        witnessPath = path.join(targetDir, files[0]);
      }
    }
    if (!witnessPath) {
      // fallback name used earlier: target/asn.gz
      witnessPath = path.join(targetDir, "asn.gz");
    }

    // 2) Run bb prove: bb prove -w witnessPath -b target/asn.json -o target/proof
    const circuitJson = path.join(targetDir, "asn.json");
    const proofOut = path.join(targetDir, "proof");
    const proveVariants = [
      {
        cmd: "bb",
        args: ["prove", "-w", witnessPath, "-b", circuitJson, "-o", proofOut],
      },
      {
        cmd: "bb",
        args: ["prove", "-w", witnessPath, "-b", circuitJson, "-o", proofOut],
      },
    ];
    let r2 = runCommands(proveVariants, CIRCUIT_DIR, 180000);
    if (!r2.ok) {
      return res
        .status(500)
        .json({ error: "prove failed", details: r2.error || r2 });
    }

    // 3) Verify with vk if present
    const vkPath = path.join(targetDir, "vk");
    let verificationOk = false;
    let verifyOutput = null;
    if (fs.existsSync(vkPath)) {
      const verifyVariants = [
        { cmd: "bb", args: ["verify", "-p", proofOut, "-v", vkPath] },
        { cmd: "bb", args: ["verify", "-p", proofOut, "-v", vkPath] },
      ];
      let r3 = runCommands(verifyVariants, CIRCUIT_DIR, 60000);
      if (r3.ok) {
        verificationOk = true;
        verifyOutput = r3.result.stdout;
      } else {
        verificationOk = false;
        verifyOutput = r3.error || "verify failed";
      }
    } else {
      verifyOutput = "vk not found; skip local verification";
    }

    // Read proof file (binary) if exists, also try JSON text if produced
    let proofContents = null;
    if (fs.existsSync(proofOut)) {
      proofContents = fs.readFileSync(proofOut);
    }

    // Return success
    return res.json({
      ok: true,
      tomlPath,
      witnessPath,
      proofPath: proofOut,
      proofSize: proofContents ? proofContents.length : null,
      verificationOk,
      verifyOutput,
    });
  } catch (err) {
    console.error("generate-proof err:", err);
    return res.status(500).json({ error: err.message || String(err) });
  }
});

app.listen(PORT, () => {
  console.log(`Backend listening on http://localhost:${PORT}`);
  console.log(`CIRCUIT_DIR = ${CIRCUIT_DIR}`);
});
