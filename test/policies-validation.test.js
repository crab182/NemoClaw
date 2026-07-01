// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Preset-validation tests for bin/lib/policies.js.
//
// These tests focus on the security-relevant validation surface that guards
// preset loading and policy merging:
//   - loadPreset() must not allow "../" traversal to read arbitrary files.
//   - parseCurrentPolicy() must reject malformed / duplicate-key / wrong-shape
//     / oversized policy reads by returning "" instead of feeding garbage into
//     the merge (which would otherwise risk an over-permissive policy).
//   - mergePresetIntoPolicy() must merge overlapping rules deterministically,
//     prefer the preset on name collision, and never throw or silently widen
//     access when given malformed or legacy-shaped input.

import fs from "node:fs";
import path from "node:path";
import { describe, it, expect } from "vitest";
import YAML from "yaml";
import policies from "../bin/lib/policies";

describe("policies preset validation", () => {
  describe("loadPreset path-traversal hardening", () => {
    it("rejects parent-directory traversal in the preset name", () => {
      // The README / SPDX'd source files live one level above the presets dir.
      // Traversal must not let those be read through loadPreset.
      expect(policies.loadPreset("../../etc/passwd")).toBe(null);
      expect(policies.loadPreset("../../../etc/shadow")).toBe(null);
      expect(policies.loadPreset("../package")).toBe(null);
      expect(policies.loadPreset("../../package")).toBe(null);
    });

    it("rejects traversal that escapes the presets dir even after .yaml is appended", () => {
      // resolves to <blueprint>/policies/etc/passwd.yaml — outside the presets dir.
      expect(policies.loadPreset("../etc/passwd")).toBe(null);
      // resolves to the presets dir's own parent, never a real preset.
      expect(policies.loadPreset("..")).toBe(null);
    });

    it("rejects absolute paths smuggled in as a preset name", () => {
      // path.resolve(dir, "/etc/passwd") => "/etc/passwd", outside presets dir.
      expect(policies.loadPreset("/etc/passwd")).toBe(null);
      expect(policies.loadPreset("/etc/hosts")).toBe(null);
    });

    it("rejects an empty preset name without falling back to the presets dir itself", () => {
      // "" would resolve to "<presets>.yaml" / the dir; must not read anything.
      expect(policies.loadPreset("")).toBe(null);
    });

    it("does not leak file contents outside the presets dir via a planted file", () => {
      // Plant a secret one level above the presets dir, then prove no traversal
      // string can read it through loadPreset.
      const aboveDir = path.dirname(policies.PRESETS_DIR);
      const secretPath = path.join(aboveDir, "validation-secret.yaml");
      let planted = false;
      try {
        fs.writeFileSync(secretPath, "secret: TOP_SECRET_VALUE\n");
        planted = true;
        for (const name of ["../validation-secret", "../../policies/validation-secret"]) {
          const result = policies.loadPreset(name);
          expect(result).toBe(null);
        }
      } finally {
        if (planted) {
          try {
            fs.unlinkSync(secretPath);
          } catch {
            /* ignore cleanup failure */
          }
        }
      }
    });

    it("still loads a legitimate preset whose name normalizes back inside the dir", () => {
      // A name containing "/.." that resolves back to a real preset is allowed
      // because the resolved path is still within the presets dir.
      const content = policies.loadPreset("foo/../pypi");
      expect(content).toBeTruthy();
      expect(content.includes("network_policies:")).toBe(true);
      expect(content.includes("pypi.org")).toBe(true);
    });

    it("returns null for a well-formed but nonexistent preset name", () => {
      expect(policies.loadPreset("does-not-exist")).toBe(null);
    });
  });

  describe("parseCurrentPolicy rejects unsafe / malformed reads", () => {
    it("drops syntactically invalid YAML rather than passing it downstream", () => {
      // Unclosed flow collection — not valid YAML.
      const raw = "Version: 3\n---\nversion: 1\nnetwork_policies: [unterminated";
      expect(policies.parseCurrentPolicy(raw)).toBe("");
    });

    it("drops duplicate-key policy bodies (strict YAML rejects them)", () => {
      // Sanity-check the underlying parser actually rejects duplicate keys,
      // then confirm parseCurrentPolicy turns that into a safe empty result.
      expect(() => YAML.parse("a: 1\na: 2")).toThrow();
      const raw = "version: 1\nversion: 2\nnetwork_policies: {}";
      expect(policies.parseCurrentPolicy(raw)).toBe("");
    });

    it("drops a top-level array body (unexpected shape) instead of accepting it", () => {
      expect(policies.parseCurrentPolicy("- a\n- b")).toBe("");
    });

    it("drops a top-level scalar body (unexpected shape)", () => {
      expect(policies.parseCurrentPolicy("just a string")).toBe("");
    });

    it("drops error/status text that is not a policy", () => {
      expect(policies.parseCurrentPolicy("Error: failed to read policy")).toBe("");
      expect(policies.parseCurrentPolicy("failed: something broke")).toBe("");
      expect(policies.parseCurrentPolicy("invalid policy state")).toBe("");
    });

    it("safely drops a large non-policy blob without throwing or hanging", () => {
      const big = "x".repeat(1_000_000);
      const start = Date.now();
      const result = policies.parseCurrentPolicy(big);
      expect(result).toBe("");
      // Guard against catastrophic backtracking / pathological slowdowns.
      expect(Date.now() - start).toBeLessThan(2000);
    });
  });

  describe("mergePresetIntoPolicy validation and determinism", () => {
    const realisticEntries =
      "  pypi_access:\n" +
      "    name: pypi_access\n" +
      "    endpoints:\n" +
      "      - host: pypi.org\n" +
      "        port: 443\n" +
      "        access: full\n";

    const existingPolicy =
      "version: 1\n\n" +
      "network_policies:\n" +
      "  npm_yarn:\n" +
      "    name: npm_yarn\n" +
      "    endpoints:\n" +
      "      - host: registry.npmjs.org\n" +
      "        port: 443\n" +
      "        access: full\n";

    it("merges overlapping rule sets deterministically (byte-for-byte stable)", () => {
      const first = policies.mergePresetIntoPolicy(existingPolicy, realisticEntries);
      const second = policies.mergePresetIntoPolicy(existingPolicy, realisticEntries);
      const third = policies.mergePresetIntoPolicy(existingPolicy, realisticEntries);
      expect(first).toBe(second);
      expect(second).toBe(third);
      // Both the existing and the preset rule survive.
      expect(first).toContain("npm_yarn");
      expect(first).toContain("pypi_access");
      expect(first).toContain("registry.npmjs.org");
      expect(first).toContain("pypi.org");
    });

    it("on name collision the preset wins and the stale endpoint is dropped", () => {
      const stale =
        "version: 1\n\n" +
        "network_policies:\n" +
        "  pypi_access:\n" +
        "    name: pypi_access\n" +
        "    endpoints:\n" +
        "      - host: stale-pypi.example.com\n" +
        "        port: 443\n" +
        "        access: full\n";
      const merged = policies.mergePresetIntoPolicy(stale, realisticEntries);
      expect(merged).toContain("pypi.org");
      expect(merged).not.toContain("stale-pypi.example.com");
      // Determinism still holds with a collision present.
      expect(policies.mergePresetIntoPolicy(stale, realisticEntries)).toBe(merged);
    });

    it("produces valid, re-parseable YAML after merging", () => {
      const merged = policies.mergePresetIntoPolicy(existingPolicy, realisticEntries);
      const parsed = YAML.parse(merged);
      expect(parsed).toBeTypeOf("object");
      expect(parsed.version).toBe(1);
      expect(parsed.network_policies.pypi_access.name).toBe("pypi_access");
      expect(parsed.network_policies.npm_yarn.name).toBe("npm_yarn");
    });

    it("does not silently emit an over-permissive policy when the current read is garbage", () => {
      // A garbage/truncated current read must be discarded and the merged
      // output must contain ONLY the requested preset, never a wildcard or
      // the leaked garbage.
      const merged = policies.mergePresetIntoPolicy("Version: 3\nHash: deadbeef", realisticEntries);
      expect(merged).toContain("pypi_access");
      expect(merged).toContain("pypi.org");
      expect(merged).not.toContain("deadbeef");
      expect(merged).not.toContain("Hash");
      // No accidental allow-all host.
      expect(merged).not.toMatch(/host:\s*['"]?\*/);
    });

    it("falls back to a text merge (without throwing) on unparseable preset entries", () => {
      const malformed = "  this is: : : not valid: yaml: [unclosed";
      let merged;
      expect(() => {
        merged = policies.mergePresetIntoPolicy("version: 1\nnetwork_policies: {}", malformed);
      }).not.toThrow();
      // The base policy is preserved; the raw entries are appended verbatim by
      // the text fallback rather than being interpreted as a permissive rule.
      expect(merged).toContain("version: 1");
      expect(merged).toContain("network_policies:");
    });

    it("handles duplicate keys inside preset entries via the text fallback without throwing", () => {
      // Duplicate map keys make the structured YAML parse throw; the merge must
      // recover via the text-based path rather than crashing.
      const dupEntries = "  r:\n    name: r\n  r:\n    name: r2\n";
      let merged;
      expect(() => {
        merged = policies.mergePresetIntoPolicy("version: 1\nnetwork_policies: {}", dupEntries);
      }).not.toThrow();
      expect(merged).toContain("version: 1");
    });

    it("replaces a legacy array-shaped network_policies with the structured preset object", () => {
      const legacyArrayCurrent = "version: 1\nnetwork_policies:\n  - host: legacy.com\n";
      const merged = policies.mergePresetIntoPolicy(legacyArrayCurrent, realisticEntries);
      const parsed = YAML.parse(merged);
      expect(parsed.network_policies.pypi_access.name).toBe("pypi_access");
      // Object form replaces the array; the merge does not throw on the shape change.
      expect(Array.isArray(parsed.network_policies)).toBe(false);
    });

    it("scaffolds a clean policy when there is no current policy", () => {
      const merged = policies.mergePresetIntoPolicy("", realisticEntries);
      const parsed = YAML.parse(merged);
      expect(parsed.version).toBe(1);
      expect(parsed.network_policies.pypi_access.name).toBe("pypi_access");
    });

    it("returns a minimal empty-network scaffold when preset entries are missing", () => {
      const merged = policies.mergePresetIntoPolicy("", "");
      expect(merged).toContain("version: 1");
      expect(merged).toContain("network_policies:");
    });

    it("handles oversized unparseable preset entries without throwing", () => {
      const bigEntries = "  " + "a".repeat(200_000);
      let merged;
      expect(() => {
        merged = policies.mergePresetIntoPolicy("version: 1\nnetwork_policies: {}", bigEntries);
      }).not.toThrow();
      expect(merged).toContain("version: 1");
    });
  });

  describe("real preset files parse as the expected shape", () => {
    it("every shipped preset parses to an object with a non-array network_policies map", () => {
      for (const p of policies.listPresets()) {
        const content = policies.loadPreset(p.name);
        const parsed = YAML.parse(content);
        expect(parsed, `${p.name} should parse to an object`).toBeTypeOf("object");
        expect(parsed.network_policies, `${p.name} has network_policies`).toBeTruthy();
        expect(
          Array.isArray(parsed.network_policies),
          `${p.name} network_policies must be a map, not an array`,
        ).toBe(false);
      }
    });

    it("merging each real preset into an empty policy yields valid, re-parseable YAML", () => {
      for (const p of policies.listPresets()) {
        const content = policies.loadPreset(p.name);
        const entries = policies.extractPresetEntries(content);
        const merged = policies.mergePresetIntoPolicy("", entries);
        expect(() => YAML.parse(merged), `${p.name} merged output must be valid YAML`).not.toThrow();
        const parsed = YAML.parse(merged);
        expect(parsed.version).toBe(1);
        expect(parsed.network_policies).toBeTruthy();
      }
    });
  });
});
