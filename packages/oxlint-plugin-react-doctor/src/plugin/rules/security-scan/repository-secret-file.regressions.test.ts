import { describe, expect, it } from "vite-plus/test";
import { runScanRule } from "../../../test-utils/run-scan-rule.js";
import { repositorySecretFile } from "./repository-secret-file.js";

describe("security-scan/repository-secret-file — regressions", () => {
  const encryptedValue =
    "ENC[AES256_GCM,data:c3ludGhldGlj,iv:aW5pdGlhbGl6YXRpb24=,tag:dGFn,type:str]";

  it("stays silent on SOPS-encrypted public env entries", () => {
    for (const relativePath of [".env", ".env.local.sops"]) {
      const findings = runScanRule(repositorySecretFile, {
        relativePath,
        content: `VITE_PUBLIC_CONTENT_TOKEN=${encryptedValue}\nNEXT_PUBLIC_API_SECRET=${encryptedValue}\nsops_version=3.9.0\n`,
      });
      expect(findings).toEqual([]);
    }
  });

  it("retains the plaintext occurrence location after an encrypted duplicate", () => {
    for (const newline of ["\n", "\r\n"]) {
      const findings = runScanRule(repositorySecretFile, {
        relativePath: ".env.local.sops",
        content: `VITE_PUBLIC_CONTENT_TOKEN=${encryptedValue}${newline}VITE_PUBLIC_CONTENT_TOKEN=synthetic-plaintext${newline}`,
      });
      expect(findings).toHaveLength(1);
      expect(findings[0]).toMatchObject({ line: 2, column: 1 });
    }
  });

  it("still flags plaintext credentials alongside encrypted entries", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath: ".env.local.sops",
      content: `VITE_PUBLIC_CONTENT_TOKEN=${encryptedValue}\nDATABASE_URL=postgres://app_prod:N7v!q2mXfA9z@db.internal.example.com:5432/app\n`,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(2);
  });

  it("does not trust a SOPS filename or malformed encryption envelope", () => {
    for (const value of [
      "synthetic-plaintext",
      "ENC[AES256_GCM,data:c3ludGhldGlj]",
      "ENC[AES256_GCM,data:plaintext!,iv:aXY=,tag:dGFn,type:str]",
      `${encryptedValue} plaintext`,
    ]) {
      const findings = runScanRule(repositorySecretFile, {
        relativePath: ".env.local.sops",
        content: `VITE_PUBLIC_CONTENT_TOKEN=${value}\n`,
      });
      expect(findings).toHaveLength(1);
    }
  });

  it("stays silent on env example files with environment suffixes", () => {
    for (const relativePath of [
      ".env.template",
      ".env.sample",
      ".env.production.template",
      ".env.local.example",
      "projects/app/.env.staging.template",
    ]) {
      const findings = runScanRule(repositorySecretFile, {
        relativePath,
        content: `MONGODB_URI="mongodb://myusername:mypassword@localhost:27017/app"\n`,
      });
      expect(findings).toHaveLength(0);
    }
  });

  it("stays silent on placeholder connection-string credentials in dev env files", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath: ".env.development",
      content: `DATABASE_URL=postgres://user:pass@127.0.0.1:5432/outline\nREDIS_URL=redis://127.0.0.1:6379\n`,
    });
    expect(findings).toHaveLength(0);
  });

  it("stays silent on same-word default credentials", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath: ".env",
      content: `DATABASE_URL=postgres://postgres:postgres@localhost:5433/oasst_web\n`,
    });
    expect(findings).toHaveLength(0);
  });

  it("still flags realistic connection-string credentials", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath: ".env",
      content: `DATABASE_URL=postgres://app_prod:N7v!q2mXfA9z@db.internal.example.com:5432/app\n`,
    });
    expect(findings).toHaveLength(1);
  });

  it("still flags environment-specific secret files", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath: ".env.production",
      content: `DATABASE_URL=postgres://app_prod:N7v!q2mXfA9z@db.internal.example.com:5432/app\n`,
    });
    expect(findings).toHaveLength(1);
  });

  it("handles pathological multi-dot env filenames without ambiguous suffix parsing", () => {
    const findings = runScanRule(repositorySecretFile, {
      relativePath:
        ".env.segment.segment.segment.segment.segment.segment.segment.segment.segment.segment.template",
      content: `DATABASE_URL=postgres://app_prod:N7v!q2mXfA9z@db.internal.example.com:5432/app\n`,
    });
    expect(findings).toEqual([]);
  });
});
