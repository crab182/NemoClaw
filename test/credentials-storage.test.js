// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Behavioural tests for the on-disk credential store in bin/lib/credentials.js.
//
// The existing credentials.test.js asserts file *contents*; this file asserts
// the security properties that were previously only checked by reading the
// source: the 0600/0700 permission enforcement, world-readable HOME rejection,
// and HOME symlink traversal. Each test re-imports the module with a fresh HOME
// because credentials.js memoises the resolved directory at module scope.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

async function importWithHome(home) {
  vi.resetModules();
  vi.stubEnv("HOME", home);
  const module = await import("../bin/lib/credentials.js");
  return module.default ?? module;
}

function mkSafeHome() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "nemoclaw-creds-"));
}

function mode(p) {
  return fs.statSync(p).mode & 0o777;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.resetModules();
  vi.unstubAllEnvs();
});

describe("credential file permission hardening", () => {
  it("writes credentials.json as 0600 and ~/.nemoclaw as 0700", async () => {
    const home = mkSafeHome();
    const creds = await importWithHome(home);

    creds.saveCredential("NVIDIA_API_KEY", "nvapi-secret");

    const dir = path.join(home, ".nemoclaw");
    const file = path.join(dir, "credentials.json");
    expect(fs.existsSync(file)).toBe(true);
    // The secret must never be group/world readable.
    expect(mode(file)).toBe(0o600);
    expect(mode(dir)).toBe(0o700);
  });

  it("re-hardens permissions even if the dir/file pre-exist with loose modes", async () => {
    const home = mkSafeHome();
    const dir = path.join(home, ".nemoclaw");
    const file = path.join(dir, "credentials.json");
    fs.mkdirSync(dir, { recursive: true, mode: 0o755 });
    fs.writeFileSync(file, "{}", { mode: 0o644 });
    fs.chmodSync(dir, 0o755);
    fs.chmodSync(file, 0o644);

    const creds = await importWithHome(home);
    creds.saveCredential("GITHUB_TOKEN", "ghp_token");

    // saveCredential chmods both back down regardless of prior state.
    expect(mode(file)).toBe(0o600);
    expect(mode(dir)).toBe(0o700);
  });

  it("creates a missing HOME tree and still applies hardened modes", async () => {
    // HOME does not exist yet -> resolveHomeDir hits the ENOENT branch.
    const base = mkSafeHome();
    const home = path.join(base, "nested", "home");
    const creds = await importWithHome(home);

    creds.saveCredential("NVIDIA_API_KEY", "nvapi-x");

    const dir = path.join(home, ".nemoclaw");
    expect(mode(dir)).toBe(0o700);
    expect(mode(path.join(dir, "credentials.json"))).toBe(0o600);
  });
});

describe("unsafe HOME rejection", () => {
  it.each(["/tmp", "/"])("refuses to store credentials when HOME is %s", async (unsafe) => {
    const creds = await importWithHome(unsafe);
    expect(() => creds.saveCredential("NVIDIA_API_KEY", "nvapi-x")).toThrow(
      /world-readable/,
    );
  });

  it("rejects a HOME symlink that resolves to a world-readable location", async () => {
    const base = mkSafeHome();
    const link = path.join(base, "home-link");
    fs.symlinkSync("/tmp", link); // traversal: safe-looking path -> /tmp

    const creds = await importWithHome(link);
    expect(() => creds.saveCredential("NVIDIA_API_KEY", "nvapi-x")).toThrow(
      /world-readable/,
    );
  });

  it("allows a HOME symlink that resolves to a user-owned directory", async () => {
    const target = mkSafeHome();
    const base = mkSafeHome();
    const link = path.join(base, "home-link");
    fs.symlinkSync(target, link);

    const creds = await importWithHome(link);
    creds.saveCredential("NVIDIA_API_KEY", "nvapi-ok");

    // Stored through the symlink; readable back and still 0600 on the real file.
    expect(creds.getCredential("NVIDIA_API_KEY")).toBe("nvapi-ok");
    expect(mode(path.join(target, ".nemoclaw", "credentials.json"))).toBe(0o600);
  });
});

describe("getCredential precedence and normalization", () => {
  it("prefers an environment variable over the stored file value", async () => {
    const home = mkSafeHome();
    const creds = await importWithHome(home);
    creds.saveCredential("NVIDIA_API_KEY", "nvapi-from-file");

    vi.stubEnv("NVIDIA_API_KEY", "  nvapi-from-env \r\n");
    // Env wins, and is normalized (CR stripped, trimmed).
    expect(creds.getCredential("NVIDIA_API_KEY")).toBe("nvapi-from-env");
  });

  it("normalizes values before they are persisted to disk", async () => {
    const home = mkSafeHome();
    const creds = await importWithHome(home);

    creds.saveCredential("NVIDIA_API_KEY", "  nvapi-padded\r\n ");

    const raw = JSON.parse(
      fs.readFileSync(path.join(home, ".nemoclaw", "credentials.json"), "utf-8"),
    );
    // No stray CR or surrounding whitespace lands in the file.
    expect(raw.NVIDIA_API_KEY).toBe("nvapi-padded");
    expect(creds.getCredential("NVIDIA_API_KEY")).toBe("nvapi-padded");
  });

  it("treats non-string normalization input as empty", async () => {
    const creds = await importWithHome("/nonexistent-but-not-unsafe");
    expect(creds.normalizeCredentialValue(undefined)).toBe("");
    expect(creds.normalizeCredentialValue(12345)).toBe("");
    expect(creds.normalizeCredentialValue(null)).toBe("");
  });
});
