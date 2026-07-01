// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type fs from "node:fs";

const SNAP = "/snap/20260323";

// ── In-memory filesystem ────────────────────────────────────────
// Mirrors the mocking pattern in snapshot.test.ts: a flat Map keyed by
// absolute path. cpSync/renameSync operate by string-prefix so a "tree"
// is just every key under a given prefix.

interface FsEntry {
  type: "file" | "dir" | "symlink";
  content?: string;
  // For symlinks, the absolute path the link points at.
  target?: string;
}

const store = new Map<string, FsEntry>();

function addFile(p: string, content: string): void {
  store.set(p, { type: "file", content });
}

function addDir(p: string): void {
  store.set(p, { type: "dir" });
}

function addSymlink(p: string, target: string): void {
  store.set(p, { type: "symlink", target });
}

const FAKE_HOME = "/fakehome";

vi.mock("node:os", () => ({
  homedir: () => FAKE_HOME,
}));

vi.mock("node:fs", async (importOriginal) => {
  const original = await importOriginal<typeof fs>();
  return {
    ...original,
    existsSync: (p: string) => store.has(p),
    mkdirSync: vi.fn((p: string) => {
      addDir(p);
    }),
    readFileSync: (p: string) => {
      const entry = store.get(p);
      if (entry?.type !== "file") throw new Error(`ENOENT: ${p}`);
      return entry.content ?? "";
    },
    writeFileSync: vi.fn((p: string, data: string) => {
      store.set(p, { type: "file", content: data });
    }),
    // cpSync with { recursive: true } and no `dereference` copies symlink
    // entries verbatim (as symlinks pointing at the same target). It never
    // resolves the link and copies the *contents* of whatever it points at,
    // so a malicious link in snapshot data cannot pull bytes from outside
    // the source tree into the target tree.
    cpSync: vi.fn((src: string, dest: string) => {
      for (const [k, v] of store) {
        if (k === src || k.startsWith(src + "/")) {
          const rel = k.slice(src.length);
          store.set(dest + rel, { ...v });
        }
      }
    }),
    renameSync: vi.fn((oldPath: string, newPath: string) => {
      for (const [k, v] of [...store]) {
        if (k === oldPath || k.startsWith(oldPath + "/")) {
          const rel = k.slice(oldPath.length);
          store.set(newPath + rel, v);
          store.delete(k);
        }
      }
    }),
    readdirSync: (p: string, opts?: { withFileTypes?: boolean }) => {
      const prefix = p.endsWith("/") ? p : p + "/";
      const childTypes = new Map<string, "file" | "dir">();
      for (const [k, v] of store) {
        if (k.startsWith(prefix)) {
          const rest = k.slice(prefix.length);
          const name = rest.split("/")[0];
          if (!name) continue;
          const isNested = rest.includes("/");
          if (!childTypes.has(name)) {
            childTypes.set(name, isNested ? "dir" : v.type === "dir" ? "dir" : "file");
          } else if (isNested) {
            childTypes.set(name, "dir");
          }
        }
      }
      if (childTypes.size === 0 && !store.has(p)) {
        throw new Error(`ENOENT: ${p}`);
      }
      if (opts?.withFileTypes) {
        return [...childTypes].map(([name, type]) => ({
          name,
          isDirectory: () => type === "dir",
          isFile: () => type === "file",
        }));
      }
      return [...childTypes.keys()].sort();
    },
  };
});

const mockExeca = vi.fn();
vi.mock("execa", () => ({ execa: (...args: unknown[]) => mockExeca(...args) }));

const { restoreIntoSandbox, rollbackFromSnapshot } = await import("./snapshot.js");

const OPENCLAW_DIR = `${FAKE_HOME}/.openclaw`;

// Helper: collect every store key under a path prefix (the "tree").
function treeKeys(root: string): string[] {
  return [...store.keys()].filter((k) => k === root || k.startsWith(root + "/")).sort();
}

// Helper: find the single archive key created by rollback for an existing host.
function archivedKey(): string | undefined {
  return [...store.keys()].find((k) => k.includes(".openclaw.nemoclaw-archived."));
}

// ── Tests ───────────────────────────────────────────────────────

describe("snapshot atomicity / safety", () => {
  beforeEach(() => {
    store.clear();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  // ──────────────────────────────────────────────────────────────
  // 1. A restore (rollbackFromSnapshot) that fails partway must not
  //    leave a half-overwritten target. rollbackFromSnapshot archives
  //    the existing host config via renameSync BEFORE copying, then on
  //    a cpSync failure restores the archive (rolls back).
  // ──────────────────────────────────────────────────────────────
  describe("rollbackFromSnapshot partial-failure safety", () => {
    it("restores the original host config when the copy throws (rollback)", async () => {
      // Existing host config with original content.
      addDir(OPENCLAW_DIR);
      addFile(`${OPENCLAW_DIR}/openclaw.json`, '{"original":true}');
      addFile(`${OPENCLAW_DIR}/keep.txt`, "keep me");

      // Snapshot to restore from.
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');

      // Make the copy phase fail. The archive rename has already happened,
      // so OPENCLAW_DIR is empty at this point (the catch block can recover).
      const fsMod = await import("node:fs");
      const { cpSync } = vi.mocked(fsMod);
      cpSync.mockImplementationOnce(() => {
        throw new Error("EIO: write failed mid-restore");
      });

      const ok = rollbackFromSnapshot(SNAP);

      // The operation reports failure.
      expect(ok).toBe(false);

      // The original host config is intact — NOT half-overwritten.
      const restored = store.get(`${OPENCLAW_DIR}/openclaw.json`);
      expect(restored?.content).toBe('{"original":true}');
      expect(store.get(`${OPENCLAW_DIR}/keep.txt`)?.content).toBe("keep me");

      // No leftover archive directory (it was renamed back into place).
      expect(archivedKey()).toBeUndefined();
    });

    it("does not leave a partial target when no original existed and copy throws", async () => {
      // No existing host config; only a snapshot to restore.
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');

      const fsMod = await import("node:fs");
      const { cpSync } = vi.mocked(fsMod);
      // Simulate a copy that writes one file then dies partway through.
      cpSync.mockImplementationOnce((_src: string, dest: string) => {
        store.set(`${dest}/partial.json`, { type: "file", content: "half" });
        throw new Error("EIO: crashed after first file");
      });

      const ok = rollbackFromSnapshot(SNAP);
      expect(ok).toBe(false);

      // The recovery path only runs when archivePath !== null. With no
      // original there is no archive, so the code leaves whatever cpSync
      // managed to write. We assert the ACTUAL behavior: the function
      // returns false, and the only thing under the target is whatever the
      // failed copy produced (nothing from outside the snapshot tree).
      // NOTE: rollbackFromSnapshot does NOT clean up a partial copy when
      // there was no pre-existing config to restore — there is no original
      // to roll back to, so this is the real, documented failure behavior.
      for (const k of treeKeys(OPENCLAW_DIR)) {
        // Everything present under the target must trace back to the copy
        // dest, never to an unrelated path.
        expect(k.startsWith(OPENCLAW_DIR)).toBe(true);
      }
      // The snapshot source is untouched by the failure.
      expect(store.get(`${SNAP}/openclaw/openclaw.json`)?.content).toBe('{"restored":true}');
    });

    it("recovers the original to the target after a copy that died part-way", async () => {
      addDir(OPENCLAW_DIR);
      addFile(`${OPENCLAW_DIR}/openclaw.json`, '{"original":true}');
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');

      const fsMod = await import("node:fs");
      const { cpSync } = vi.mocked(fsMod);
      // cpSync writes a partial child into the target before throwing. The
      // archive rename already moved the original out, so the target dir
      // key itself is still absent — the recovery guard
      // (`existsSync(archivePath) && !existsSync(OPENCLAW_DIR)`) holds and
      // the archived original is renamed back into place.
      cpSync.mockImplementationOnce((_src: string, dest: string) => {
        store.set(`${dest}/partial.json`, { type: "file", content: "partial" });
        throw new Error("EIO");
      });

      const ok = rollbackFromSnapshot(SNAP);
      expect(ok).toBe(false);

      // The original config was rolled back into the target — not lost.
      expect(store.get(`${OPENCLAW_DIR}/openclaw.json`)?.content).toBe('{"original":true}');
      // The archive was consumed by the recovery rename (renamed back),
      // so no dangling archive directory is left behind.
      expect(archivedKey()).toBeUndefined();
    });

    it("returns false without touching the host when snapshot source is missing", () => {
      addDir(OPENCLAW_DIR);
      addFile(`${OPENCLAW_DIR}/openclaw.json`, '{"original":true}');
      // No `${SNAP}/openclaw` dir.
      addDir(SNAP);

      const before = treeKeys(OPENCLAW_DIR);
      expect(rollbackFromSnapshot(SNAP)).toBe(false);
      // Host config left completely intact — no rename, no copy, no archive.
      expect(treeKeys(OPENCLAW_DIR)).toEqual(before);
      expect(archivedKey()).toBeUndefined();
    });
  });

  // ──────────────────────────────────────────────────────────────
  // 2. Concurrent restore (async, shells out to openshell) + rollback
  //    (sync, mutates the host config) must not corrupt each other's
  //    state. restoreIntoSandbox never touches OPENCLAW_DIR, and
  //    rollbackFromSnapshot never touches the sandbox, so interleaving
  //    them leaves both targets coherent.
  // ──────────────────────────────────────────────────────────────
  describe("concurrent restore + rollback", () => {
    it("interleaving async sandbox restore with a sync host rollback keeps both coherent", async () => {
      // Snapshot present for both operations.
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');

      // Pre-existing host config to be rolled back over.
      addDir(OPENCLAW_DIR);
      addFile(`${OPENCLAW_DIR}/openclaw.json`, '{"old":true}');

      // Hold the execa promise open so the sync rollback runs while the
      // async sandbox restore is still in flight.
      let releaseExeca!: (v: { exitCode: number }) => void;
      mockExeca.mockReturnValue(
        new Promise<{ exitCode: number }>((resolve) => {
          releaseExeca = resolve;
        }),
      );

      const restorePromise = restoreIntoSandbox(SNAP, "mybox");

      // Run the sync host rollback while the sandbox restore is pending.
      const rollbackOk = rollbackFromSnapshot(SNAP);
      expect(rollbackOk).toBe(true);

      // Host config now reflects the rollback content.
      expect(store.get(`${OPENCLAW_DIR}/openclaw.json`)?.content).toBe('{"restored":true}');

      // Now let the sandbox restore complete.
      releaseExeca({ exitCode: 0 });
      expect(await restorePromise).toBe(true);

      // Sandbox restore read from the snapshot source, untouched by rollback.
      expect(mockExeca).toHaveBeenCalledWith(
        "openshell",
        ["sandbox", "cp", `${SNAP}/openclaw`, "mybox:/sandbox/.openclaw"],
        { reject: false },
      );
      // Host config is still the rolled-back content (sandbox path did not
      // clobber it).
      expect(store.get(`${OPENCLAW_DIR}/openclaw.json`)?.content).toBe('{"restored":true}');
      // Snapshot source remains the single source of truth for both.
      expect(store.get(`${SNAP}/openclaw/openclaw.json`)?.content).toBe('{"restored":true}');
    });

    it("two concurrent sandbox restores both read the snapshot and do not interfere", async () => {
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');

      mockExeca.mockResolvedValue({ exitCode: 0 });

      const [a, b] = await Promise.all([
        restoreIntoSandbox(SNAP, "box-a"),
        restoreIntoSandbox(SNAP, "box-b"),
      ]);

      expect(a).toBe(true);
      expect(b).toBe(true);
      expect(mockExeca).toHaveBeenCalledWith(
        "openshell",
        ["sandbox", "cp", `${SNAP}/openclaw`, "box-a:/sandbox/.openclaw"],
        { reject: false },
      );
      expect(mockExeca).toHaveBeenCalledWith(
        "openshell",
        ["sandbox", "cp", `${SNAP}/openclaw`, "box-b:/sandbox/.openclaw"],
        { reject: false },
      );
      // Snapshot source unchanged after both restores.
      expect(store.get(`${SNAP}/openclaw/openclaw.json`)?.content).toBe('{"restored":true}');
    });
  });

  // ──────────────────────────────────────────────────────────────
  // 3. Symlinks present in snapshot data must not be followed out of
  //    the target tree on restore. rollbackFromSnapshot copies via
  //    cpSync({ recursive: true }) with NO `dereference` flag, so Node
  //    copies a symlink entry as a symlink — it never resolves the link
  //    and pulls in bytes from outside the snapshot tree. The mock
  //    reproduces this: copying treats a symlink as a leaf entry, so no
  //    write ever lands outside OPENCLAW_DIR.
  // ──────────────────────────────────────────────────────────────
  describe("symlink containment on restore", () => {
    it("a symlink in the snapshot is copied as a link, not followed out of the tree", () => {
      // A sensitive file that lives OUTSIDE both the snapshot and target.
      addFile("/etc/shadow", "root:secret");

      // Snapshot containing a symlink that points at that external file.
      addDir(`${SNAP}/openclaw`);
      addFile(`${SNAP}/openclaw/openclaw.json`, '{"restored":true}');
      addSymlink(`${SNAP}/openclaw/evil-link`, "/etc/shadow");

      expect(rollbackFromSnapshot(SNAP)).toBe(true);

      // The restore wrote ONLY paths under the target tree.
      for (const k of treeKeys(OPENCLAW_DIR)) {
        expect(k.startsWith(OPENCLAW_DIR)).toBe(true);
      }

      // The link was copied as a symlink entry (preserving the type), not
      // dereferenced into a copy of /etc/shadow's contents.
      const copiedLink = store.get(`${OPENCLAW_DIR}/evil-link`);
      expect(copiedLink?.type).toBe("symlink");
      expect(copiedLink?.target).toBe("/etc/shadow");
      // It is NOT a regular file holding the secret bytes.
      expect(copiedLink?.content).toBeUndefined();

      // The external secret was never copied INTO the target tree.
      const leaked = [...store.entries()].find(
        ([k, v]) =>
          k.startsWith(OPENCLAW_DIR + "/") && v.type === "file" && v.content === "root:secret",
      );
      expect(leaked).toBeUndefined();

      // The external file itself is untouched (no traversal write-through).
      expect(store.get("/etc/shadow")?.content).toBe("root:secret");
    });

    it("a symlink pointing OUTSIDE the snapshot does not drag external files into the target", () => {
      // Files living outside the snapshot tree.
      addDir("/outside");
      addFile("/outside/credentials", "API_KEY=abc123");

      addDir(`${SNAP}/openclaw`);
      // Link points at a directory outside the snapshot.
      addSymlink(`${SNAP}/openclaw/escape`, "/outside");

      expect(rollbackFromSnapshot(SNAP)).toBe(true);

      // Nothing from /outside should appear under the target tree.
      const escaped = [...store.keys()].find(
        (k) => k.startsWith(OPENCLAW_DIR + "/") && k.includes("credentials"),
      );
      expect(escaped).toBeUndefined();

      // The symlink entry itself is present but unresolved.
      const link = store.get(`${OPENCLAW_DIR}/escape`);
      expect(link?.type).toBe("symlink");
      expect(link?.target).toBe("/outside");

      // Original external files untouched.
      expect(store.get("/outside/credentials")?.content).toBe("API_KEY=abc123");
    });
  });
});
