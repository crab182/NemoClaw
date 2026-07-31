// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const DOCKERFILE_BASE = path.join(import.meta.dirname, "..", "Dockerfile.base");

describe("Dockerfile.base OpenClaw writable state layout", () => {
  const src = fs.readFileSync(DOCKERFILE_BASE, "utf-8");

  it.each([
    ["exec-approvals.json", "file"],
    ["telegram", "directory"],
    ["credentials", "directory"],
  ])("keeps %s writable through .openclaw-data", (name, type) => {
    const dataPath = `/sandbox/.openclaw-data/${name}`;
    const linkPath = `/sandbox/.openclaw/${name}`;

    if (type === "file") {
      expect(src).toContain(`touch ${dataPath}`);
    } else {
      expect(src).toMatch(new RegExp(`\\s${dataPath}(?:\\s|\\\\)`));
    }

    expect(src).toContain(`ln -s ${dataPath} ${linkPath}`);
  });
});
