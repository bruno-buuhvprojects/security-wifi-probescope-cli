// Classificacao de enderecos MAC e resolucao de fabricante.
//
// Desde iOS 8 e Android 10, clientes usam um MAC aleatorio ao emitir probe
// requests. O bit U/L (bit 1 do primeiro octeto) distingue um endereco
// localmente administrado -- isto e, aleatorio -- de um endereco globalmente
// unico gravado no chip. So o endereco global tem OUI atribuido pelo IEEE e,
// portanto, fabricante identificavel.
//
// A consulta de fabricante acontece por OUI -- nunca pelo MAC completo -- e e
// executada fora do caminho de captura, para nao descartar quadros enquanto se
// espera a rede responder.

import { readFileSync } from "node:fs";

/** Resultado da leitura dos bits de controle de um MAC. */
export interface MacClassification {
  isValid: boolean;
  isRandomized: boolean;
  isMulticast: boolean;
  oui: string | null;
}

const MAC_RE = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;

/** Bit 0 do primeiro octeto: endereco de grupo (multicast/broadcast). */
const MULTICAST_BIT = 0x01;
/** Bit 1 do primeiro octeto: endereco localmente administrado (aleatorio). */
const LOCALLY_ADMINISTERED_BIT = 0x02;

/** Classifica um MAC quanto a randomizacao, escopo e OUI. */
export function classify(mac: string | null | undefined): MacClassification {
  if (!mac) {
    return { isValid: false, isRandomized: false, isMulticast: false, oui: null };
  }

  const normalized = mac.trim().toLowerCase();
  if (!MAC_RE.test(normalized)) {
    return { isValid: false, isRandomized: false, isMulticast: false, oui: null };
  }

  const firstOctet = parseInt(normalized.slice(0, 2), 16);
  const isRandomized = (firstOctet & LOCALLY_ADMINISTERED_BIT) !== 0;
  const isMulticast = (firstOctet & MULTICAST_BIT) !== 0;

  // O OUI de um endereco aleatorio nao corresponde a fabricante algum;
  // devolve-lo induziria o analista a uma atribuicao falsa.
  const oui = isRandomized ? null : normalized.slice(0, 8);

  return { isValid: true, isRandomized, isMulticast, oui };
}

/** So enderecos globais tem OUI registrado no IEEE. */
export function vendorResolvable(c: MacClassification): boolean {
  return c.isValid && !c.isRandomized && c.oui !== null;
}

const API_URL = "https://api.macvendors.com/";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resolve fabricante a partir do OUI, com base local e API opcional.
 *
 * A resolucao e deliberadamente separada da captura: `resolveAll` e chamada
 * depois que o sniffing termina, sobre o conjunto de OUIs distintos observados.
 * Isso elimina a perda de quadros causada por I/O de rede dentro do callback de
 * captura e reduz drasticamente o numero de requisicoes.
 */
export class VendorResolver {
  private enabled: boolean;
  private timeoutMs: number;
  private cache: Map<string, string> = new Map();

  constructor(opts?: { enabled?: boolean; localDb?: string; timeoutMs?: number }) {
    this.enabled = opts?.enabled ?? false;
    this.timeoutMs = opts?.timeoutMs ?? 3000;
    if (opts?.localDb) {
      this.loadLocalDb(opts.localDb);
    }
  }

  /** Carrega base offline no formato `OUI,Fabricante` por linha. */
  private loadLocalDb(path: string): void {
    try {
      const content = readFileSync(path, "utf-8");
      for (const rawLine of content.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith("#")) {
          continue;
        }
        const idx = line.indexOf(",");
        if (idx === -1) {
          continue;
        }
        const oui = line.slice(0, idx).trim().toLowerCase().replace(/-/g, ":");
        const vendor = line.slice(idx + 1).trim();
        if (oui && vendor) {
          this.cache.set(oui, vendor);
        }
      }
      console.error(`Base local de OUI carregada: ${this.cache.size} registros`);
    } catch (exc) {
      console.error(`Nao foi possivel ler a base local de OUI: ${String(exc)}`);
    }
  }

  /** Resolve um conjunto de OUIs, consultando a rede so se preciso. */
  async resolveAll(ouis: Set<string>): Promise<Record<string, string>> {
    const result: Record<string, string> = {};
    for (const oui of ouis) {
      const cached = this.cache.get(oui);
      if (cached !== undefined) {
        result[oui] = cached;
      }
    }

    const pending = [...ouis].filter((oui) => !(oui in result)).sort();

    if (pending.length === 0) {
      return result;
    }
    if (!this.enabled) {
      // Sem consulta online, o que nao esta na base local fica rotulado como
      // nao consultado em vez de receber um rotulo adivinhado.
      for (const oui of pending) {
        result[oui] = "Não consultado";
      }
      return result;
    }

    Object.assign(result, await this.resolveOnline(pending));
    return result;
  }

  /** Consulta a API publica por OUI, tolerando falha e rate limit. */
  private async resolveOnline(ouis: string[]): Promise<Record<string, string>> {
    const resolved: Record<string, string> = {};

    for (const oui of ouis) {
      let vendor: string;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        let response: Response;
        try {
          response = await fetch(API_URL + oui, { signal: controller.signal });
        } finally {
          clearTimeout(timer);
        }

        if (response.status === 200) {
          vendor = (await response.text()).trim();
        } else if (response.status === 404) {
          vendor = "Desconhecido";
        } else if (response.status === 429) {
          console.error(
            "Limite de requisicoes atingido na API de fabricantes; interrompendo consultas",
          );
          resolved[oui] = "Limite excedido";
          break;
        } else {
          vendor = "Desconhecido";
        }
      } catch {
        // Rede e melhor degradar que abortar.
        vendor = "Falha na consulta";
      }

      resolved[oui] = vendor;
      this.cache.set(oui, vendor);
      // A API publica limita a ~1 req/s; o atraso vive aqui, fora da captura,
      // onde custa apenas tempo de pos-processamento.
      await sleep(1000);
    }

    for (const oui of ouis) {
      if (!(oui in resolved)) {
        resolved[oui] = "Não consultado";
      }
    }
    return resolved;
  }
}
