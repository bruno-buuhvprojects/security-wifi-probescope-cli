// Pseudonimizacao de identificadores de dispositivo.
//
// Dois modos de operacao, escolhidos explicitamente pelo operador:
//
//   "masked" (padrao): o MAC nunca aparece em claro. Cada MAC vira um
//     pseudonimo HMAC-SHA256 com salt aleatorio por sessao. Descartado o salt
//     ao fim da execucao, o pseudonimo nao e reversivel nem correlacionavel
//     entre capturas, mas continua estavel dentro da mesma captura.
//
//   "reveal": o MAC aparece em claro. Destinado a laboratorio controlado. O
//     modo fica registrado nos metadados do arquivo exportado.
//
// O salt pode ser fixado quando o estudo exige comparar sessoes distintas; isso
// reintroduz a correlacao entre capturas e por isso e opt-in.

import { createHmac, randomBytes } from "node:crypto";

/** Modo de tratamento dos identificadores capturados. */
export type AnonymizationMode = "masked" | "reveal";
export const AnonymizationMode = { MASKED: "masked", REVEAL: "reveal" } as const;

/** Tamanho, em caracteres hexadecimais, do pseudonimo exibido. */
const DIGEST_CHARS = 12;

/** Converte MACs em pseudonimos estaveis dentro de uma sessao. */
export class MacAnonymizer {
  private mode: AnonymizationMode;
  private persistentSalt: boolean;
  private saltBuffer: Buffer;

  constructor(opts?: { mode?: AnonymizationMode; salt?: string | null }) {
    this.mode = opts?.mode ?? "masked";
    const salt = opts?.salt ?? null;
    // Salt explicito permite correlacionar sessoes; sem ele, cada execucao e um
    // universo isolado.
    this.persistentSalt = salt !== null;
    this.saltBuffer = salt !== null ? Buffer.from(salt, "utf8") : randomBytes(32);
  }

  /** Normaliza o MAC para minusculas com separador ':'. */
  static normalize(mac: string): string {
    return mac.trim().toLowerCase();
  }

  /** Retorna o pseudonimo HMAC de um MAC, independente do modo. */
  pseudonym(mac: string): string {
    const normalized = MacAnonymizer.normalize(mac);
    const digest = createHmac("sha256", this.saltBuffer)
      .update(normalized, "utf8")
      .digest("hex");
    return "id:" + digest.slice(0, DIGEST_CHARS);
  }

  /**
   * Retorna o identificador conforme o modo configurado.
   *
   * E o unico ponto do programa autorizado a decidir entre MAC em claro e
   * pseudonimo, para que console e arquivo exportado nunca divirjam.
   */
  represent(mac: string | null | undefined): string {
    if (!mac) {
      return "N/A";
    }
    if (this.mode === "reveal") {
      return MacAnonymizer.normalize(mac);
    }
    return this.pseudonym(mac);
  }

  /** Indica se a saida contera dado pessoal em claro. */
  get revealsIdentifiers(): boolean {
    return this.mode === "reveal";
  }

  /** Metadados sobre o tratamento aplicado, embutidos no export. */
  provenance(): Record<string, unknown> {
    return {
      anonymization_mode: this.mode,
      contains_plaintext_identifiers: this.revealsIdentifiers,
      salt_scope: this.persistentSalt ? "fixed" : "per-session",
      pseudonym_algorithm: "HMAC-SHA256 truncated to 12 hex chars",
    };
  }
}
