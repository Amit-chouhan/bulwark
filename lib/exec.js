const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const REPO_DIR = process.env.REPO_DIR || path.resolve(__dirname, "../../admin");

function getSafeCwd(cwd) {
  const target = cwd || REPO_DIR;
  return fs.existsSync(target) ? target : process.cwd();
}

function attachStreams(child, resolve, reject) {
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (d) => (stdout += d.toString()));
  child.stderr.on("data", (d) => (stderr += d.toString()));
  child.on("close", (code) => resolve({ stdout, stderr, code }));
  child.on("error", reject);
}

function writeStdin(child, input) {
  if (input === undefined || input === null) return;
  child.stdin.on("error", () => {});
  child.stdin.end(String(input));
}

function execCommand(cmd, opts = {}) {
  return new Promise((resolve, reject) => {
    const shell = os.platform() === "win32" ? "cmd" : "bash";
    const shellFlag = os.platform() === "win32" ? "/c" : "-c";
    const child = spawn(shell, [shellFlag, cmd], {
      cwd: getSafeCwd(opts.cwd),
      timeout: opts.timeout || 15000,
      env: { ...process.env, ...(opts.env || {}) },
    });
    attachStreams(child, resolve, reject);
    writeStdin(child, opts.stdin);
  });
}

function execFileCommand(command, args = [], opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: getSafeCwd(opts.cwd),
      timeout: opts.timeout || 15000,
      env: { ...process.env, ...(opts.env || {}) },
      shell: false,
    });
    attachStreams(child, resolve, reject);
    writeStdin(child, opts.stdin);
  });
}

module.exports = { execCommand, execFileCommand, REPO_DIR };
