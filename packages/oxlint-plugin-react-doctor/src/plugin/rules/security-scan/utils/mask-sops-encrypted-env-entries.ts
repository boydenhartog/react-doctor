const SOPS_ENCRYPTED_ENV_ENTRY_PATTERN =
  /^[\t ]*(?:export[\t ]+)?[A-Za-z_][A-Za-z0-9_]*[\t ]*=[\t ]*ENC\[AES256_GCM,data:[A-Za-z0-9+/]*={0,2},iv:[A-Za-z0-9+/]+={0,2},tag:[A-Za-z0-9+/]+={0,2},type:str\][\t ]*(?=\r?$)/gm;

export const maskSopsEncryptedEnvEntries = (content: string): string =>
  content.replace(SOPS_ENCRYPTED_ENV_ENTRY_PATTERN, (entry) => " ".repeat(entry.length));
