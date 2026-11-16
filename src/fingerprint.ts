// Impressao digital de dispositivo a partir dos Information Elements.
//
// Um probe request carrega, alem do SSID procurado, uma lista de Information
// Elements (IEs) que descrevem as capacidades de radio do cliente. Essa
// combinacao e determinada pelo chipset e pelo driver, nao pelo endereco MAC --
// por isso permanece estavel quando o dispositivo randomiza o MAC.
//
// A assinatura nao identifica uma pessoa: ela identifica um modelo/driver, e em
// ambientes densos varios aparelhos colidem no mesmo grupo. O relatorio trata o
// resultado como agrupamento aproximado, nunca como identidade.

import { createHash } from "node:crypto";

/**
 * IEs cujo conteudo integral entra na assinatura por serem estaveis por modelo
 * e ricos em bits discriminantes:
 *   1 Supported Rates; 45 HT Capabilities; 50 Extended Supported Rates;
 *   127 Extended Capabilities; 191 VHT Capabilities; 255 Element ID Extension.
 */
export const CONTENT_SENSITIVE_IDS: Set<number> = new Set([1, 45, 50, 127, 191, 255]);

/** Element ID de blocos proprietarios; entra na assinatura apenas o OUI. */
export const VENDOR_SPECIFIC_ID = 221;

/** OUI do Wi-Fi Alliance usado pelo WPS, util como traco adicional. */
const WPS_OUI = "00:50:f2";

/** Formata um Buffer como hex com separador ':' (ex.: "00:50:f2"). */
function hexWithColons(buf: Buffer): string {
  return Array.from(buf, (b) => b.toString(16).padStart(2, "0")).join(":");
}

/** Assinatura derivada dos IEs de um probe request. */
export class ProbeFingerprint {
  /** Ordem em que os Element IDs aparecem no quadro. */
  elementOrder: number[];
  /** Conteudo hexadecimal dos IEs discriminantes, por ID. */
  elementPayloads: Map<number, string>;
  /** OUIs dos blocos vendor specific, na ordem de ocorrencia. */
  vendorOuis: string[];

  constructor(
    elementOrder: number[] = [],
    elementPayloads: Map<number, string> = new Map(),
    vendorOuis: string[] = [],
  ) {
    this.elementOrder = elementOrder;
    this.elementPayloads = elementPayloads;
    this.vendorOuis = vendorOuis;
  }

  /** Hash estavel da assinatura, usado como chave de agrupamento. */
  get digest(): string {
    const payloadIds = [...this.elementPayloads.keys()].sort((a, b) => a - b);
    const parts = [
      this.elementOrder.join(","),
      payloadIds.map((id) => `${id}=${this.elementPayloads.get(id)}`).join(";"),
      this.vendorOuis.join(","),
    ];
    const raw = parts.join("|");
    return "fp:" + createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 12);
  }

  /** Indica presenca de bloco WPS entre os vendor specific. */
  get hasWps(): boolean {
    return this.vendorOuis.includes(WPS_OUI);
  }

  /** Representacao serializavel para CSV/JSON e para o relatorio. */
  asDict(): Record<string, unknown> {
    const payloads: Record<number, string> = {};
    for (const [id, hex] of this.elementPayloads) {
      payloads[id] = hex;
    }
    return {
      digest: this.digest,
      element_order: [...this.elementOrder],
      element_payloads: payloads,
      vendor_ouis: [...this.vendorOuis],
      has_wps: this.hasWps,
    };
  }
}

/**
 * Monta a assinatura a partir dos pares `[elementId, payload]`.
 *
 * Recebe elementos ja extraidos do quadro para manter o modulo independente da
 * camada de captura e, com isso, testavel com vetores sinteticos.
 */
export function buildFingerprint(elements: Array<[number, Buffer]>): ProbeFingerprint {
  const order: number[] = [];
  const payloads = new Map<number, string>();
  const ouis: string[] = [];

  for (const [elementId, payload] of elements) {
    order.push(elementId);

    if (elementId === VENDOR_SPECIFIC_ID) {
      // So o OUI entra: o corpo costuma trazer estado variavel (contadores,
      // flags de sessao) que instabilizaria a assinatura.
      if (payload.length >= 3) {
        ouis.push(hexWithColons(payload.subarray(0, 3)));
      }
      continue;
    }

    if (CONTENT_SENSITIVE_IDS.has(elementId)) {
      // Um mesmo ID repetido tem o conteudo concatenado, preservando a
      // diferenca entre quadros com e sem a repeticao.
      const previous = payloads.get(elementId) ?? "";
      payloads.set(elementId, previous + payload.toString("hex"));
    }
  }

  return new ProbeFingerprint(order, payloads, ouis);
}
