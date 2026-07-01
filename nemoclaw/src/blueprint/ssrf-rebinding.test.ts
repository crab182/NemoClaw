// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// DNS-rebinding tests for SSRF validation (PSIRT bug 6002763).
//
// These exercise the resolve-then-pivot threat: a hostname that resolves to a
// public IP on one lookup and to a private/metadata IP on another, plus a
// multi-record answer that contains both a public and a private address.
//
// The validator's DNS seam is `dnsPromises.lookup(hostname, { all: true })`,
// mocked here exactly as in ssrf.test.ts. NOTE: validateEndpointUrl resolves
// the hostname once per call and returns the *URL string* — it does not pin
// the resolved IP. A classic TOCTOU rebind (validate against a public IP, then
// reconnect to a private IP at fetch time) is therefore not expressible as a
// single call against the real API. We test the rebinding behavior that IS
// observable: (1) every validation call re-resolves, so a host that has
// rebound to a private IP is rejected at the point validation runs, and
// (2) a single answer mixing public and private records is rejected because
// the validator checks *all* returned addresses.

import { describe, it, expect, vi } from "vitest";

type LookupResult = Array<{ address: string; family: number }>;
const mockLookup = vi.fn<(hostname: string, options: { all: true }) => Promise<LookupResult>>();

vi.mock("node:dns", () => ({
  promises: { lookup: (...args: unknown[]) => mockLookup(...(args as [string, { all: true }])) },
}));

const { validateEndpointUrl } = await import("./ssrf.js");

const PUBLIC = "93.184.216.34";

function rec(address: string, family = 4): { address: string; family: number } {
  return { address, family };
}

// ── Resolve-then-pivot (sequential rebinding) ───────────────────────

describe("DNS rebinding: resolve-then-pivot", () => {
  it.each([
    ["169.254.169.254", "cloud metadata endpoint"],
    ["10.0.0.5", "private 10/8"],
    ["127.0.0.1", "localhost"],
    ["192.168.1.10", "private 192.168/16"],
  ])("rejects a host that pivots from public to %s on a later resolution", async (privateIp) => {
    // First resolution: a benign public IP — validation passes.
    mockLookup.mockResolvedValueOnce([rec(PUBLIC)]);
    // Second resolution: the host has rebound to a private/metadata IP.
    mockLookup.mockResolvedValueOnce([rec(privateIp)]);

    const url = "https://rebind.attacker.example/v1";

    // The first validation sees only the public answer and succeeds.
    await expect(validateEndpointUrl(url)).resolves.toBe(url);

    // Because validation re-resolves every call, the pivoted (rebound)
    // private answer is caught the next time the URL is validated.
    await expect(validateEndpointUrl(url)).rejects.toThrow(/private\/internal address/);
  });

  it("re-resolves on every call rather than caching the first answer", async () => {
    // mockLookup is a module-level mock shared across tests, so assert on the
    // call-count delta for this test rather than an absolute total.
    const before = mockLookup.mock.calls.length;
    mockLookup.mockResolvedValueOnce([rec(PUBLIC)]);
    mockLookup.mockResolvedValueOnce([rec("169.254.169.254")]);

    const url = "https://rebind.attacker.example/metadata";
    await expect(validateEndpointUrl(url)).resolves.toBe(url);
    await expect(validateEndpointUrl(url)).rejects.toThrow(/169\.254\.169\.254/);

    // Two distinct lookups happened — the validator did not cache the first.
    expect(mockLookup.mock.calls.length - before).toBe(2);
  });

  it("rejects when the very first (and only) resolution is a private metadata IP", async () => {
    // A host that resolves straight to the metadata service — the simplest
    // rebind outcome, asserted to confirm no public-first grace is granted.
    mockLookup.mockResolvedValue([rec("169.254.169.254")]);
    await expect(validateEndpointUrl("https://rebind.attacker.example/")).rejects.toThrow(
      /private\/internal address/,
    );
  });
});

// ── Multi-record answer mixing public + private (single-answer rebind) ──

describe("DNS rebinding: mixed public + private in one answer", () => {
  it.each([
    ["169.254.169.254", "metadata"],
    ["10.0.0.1", "private 10/8"],
    ["127.0.0.1", "localhost"],
    ["172.16.0.1", "private 172.16/12"],
    ["192.168.0.1", "private 192.168/16"],
    ["100.64.0.1", "CGNAT 100.64/10"],
  ])("rejects when a single answer contains public + %s", async (privateIp) => {
    mockLookup.mockResolvedValue([rec(PUBLIC), rec(privateIp)]);
    await expect(validateEndpointUrl("https://multi.attacker.example/v1")).rejects.toThrow(
      /private\/internal address/,
    );
  });

  it("rejects even when the private record is ordered before the public one", async () => {
    mockLookup.mockResolvedValue([rec("10.0.0.1"), rec(PUBLIC)]);
    await expect(validateEndpointUrl("https://multi.attacker.example/v1")).rejects.toThrow(
      /private\/internal address/,
    );
  });

  it("names the offending private address in the rejection", async () => {
    mockLookup.mockResolvedValue([rec(PUBLIC), rec("169.254.169.254")]);
    await expect(validateEndpointUrl("https://multi.attacker.example/v1")).rejects.toThrow(
      /169\.254\.169\.254/,
    );
  });

  it("rejects an IPv4-mapped IPv6 private record hidden among public records", async () => {
    // family=6 IPv4-mapped form (::ffff:127.0.0.1) must still be unwrapped and
    // rejected even when paired with a legitimate public address.
    mockLookup.mockResolvedValue([rec(PUBLIC), rec("::ffff:127.0.0.1", 6)]);
    await expect(validateEndpointUrl("https://multi.attacker.example/v1")).rejects.toThrow(
      /private\/internal address/,
    );
  });

  it("allows a multi-record answer that is entirely public", async () => {
    mockLookup.mockResolvedValue([rec(PUBLIC), rec("8.8.8.8"), rec("1.1.1.1")]);
    const url = "https://multi.legit.example/v1";
    await expect(validateEndpointUrl(url)).resolves.toBe(url);
  });
});
