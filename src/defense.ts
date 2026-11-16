// Contramedidas: medir a exposicao e demonstrar como reduzi-la.
//
// O fluxo do trabalho e: capturar, evidenciar o risco (inference.ts) e entao
// responder "como alguem se defende disto". Este modulo fecha esse ciclo em duas
// frentes.
//
// 1. Diagnostico -- para cada dispositivo observado, atribui um nivel de
//    exposicao a partir de sinais objetivos da captura (usou MAC fixo? vazou a
//    PNL? emitiu SSID distintivo? foi reagrupado por fingerprint apesar de
//    randomizar?).
//
// 2. Simulacao de defesa -- reexecuta a mesma analise sobre uma copia dos dados
//    com cada contramedida aplicada, de modo a mostrar, com numero, quanto cada
//    medida teria reduzido do que foi inferido. E a demonstracao que a banca
//    pede: nao "a defesa funciona", mas "a defesa derruba X de Y vinculos
//    sociais e zera a PNL exposta".
//
// O ponto pedagogico central: a randomizacao de MAC sozinha NAO zera o risco,
// porque a PNL e o fingerprint sobrevivem a ela. So a supressao da PNL fecha o
// vetor dominante.

import { CaptureStore } from "./models.js";
import { assess, devicePopularity, distinctive } from "./inference.js";
import type { ExposureScoreDto, CountermeasureRow } from "./schemas.js";

/** Interface minima do anonimizador usada aqui: so a conversao para exibicao. */
interface Representer {
  represent(mac: string | null | undefined): string;
}

/** Nivel de exposicao de um dispositivo e o porque. */
export class ExposureScore {
  deviceId: string;
  score: number;
  level: string;
  reasons: string[];

  constructor(init: {
    deviceId: string;
    score: number;
    level: string;
    reasons: string[];
  }) {
    this.deviceId = init.deviceId;
    this.score = init.score;
    this.level = init.level;
    this.reasons = init.reasons;
  }

  asDict(): Record<string, unknown> {
    const dto: ExposureScoreDto = {
      device_id: this.deviceId,
      score: this.score,
      level: this.level,
      reasons: this.reasons,
    };
    return dto;
  }
}

/** Rotulos por faixa de pontuacao, do menor para o maior risco. */
const LEVELS: Array<[number, string]> = [
  [0, "mínima"], [1, "baixa"], [3, "moderada"], [5, "alta"],
];

function levelFor(score: number): string {
  let label = LEVELS[0][1];
  for (const [threshold, name] of LEVELS) {
    if (score >= threshold) {
      label = name;
    }
  }
  return label;
}

/**
 * Pontua a exposicao de cada dispositivo a partir da captura.
 *
 * A pontuacao e a soma de sinais independentes; cada um aponta um vetor de
 * inferencia que aquele dispositivo deixou aberto. Serve para priorizar quem
 * esta mais exposto, nao como indice absoluto.
 */
export function scoreDevices(
  store: CaptureStore,
  anonymizer: Representer,
): ExposureScore[] {
  const popularity = devicePopularity(store);

  // Fingerprints que reunem mais de um MAC: indicio de reagrupamento.
  const multiMacFps = new Set<string>();
  for (const [fp, macs] of store.fingerprintGroups) {
    if (macs.size > 1) {
      multiMacFps.add(fp);
    }
  }

  const scores: ExposureScore[] = [];
  for (const device of store.devices.values()) {
    let points = 0;
    const reasons: string[] = [];

    if (!device.isRandomized) {
      points += 2;
      reasons.push("MAC fixo (globalmente único): rastreável entre "
        + "sessões e com fabricante identificável");
    }

    if (device.ssids.size > 0) {
      points += 2;
      reasons.push("Revelou a lista de redes preferidas "
        + `(${device.ssids.size} SSID(s))`);
    }

    const distinct = distinctive(device.ssids, popularity);
    if (distinct.length > 0) {
      points += 1;
      reasons.push("Emitiu SSID(s) distintivo(s) que funcionam como "
        + `quase-identificador: ${distinct.join(", ")}`);
    }

    if (device.isRandomized && hasIntersection(device.fingerprints, multiMacFps)) {
      points += 1;
      reasons.push("Randomizou o MAC, mas a assinatura de rádio foi "
        + "reagrupada com outros endereços (randomização "
        + "contornada por fingerprint)");
    }

    if (reasons.length === 0) {
      reasons.push("Sem vetores de inferência relevantes nesta captura");
    }

    scores.push(new ExposureScore({
      deviceId: anonymizer.represent(device.macAddress),
      score: points,
      level: levelFor(points),
      reasons,
    }));
  }

  scores.sort((a, b) => b.score - a.score);
  return scores;
}

/** Verdadeiro se os dois conjuntos tem ao menos um elemento em comum. */
function hasIntersection(a: Set<string>, b: Set<string>): boolean {
  for (const item of a) {
    if (b.has(item)) {
      return true;
    }
  }
  return false;
}

/**
 * Copia a captura aplicando uma contramedida hipotetica.
 *
 * Trabalha sobre copia: a simulacao jamais altera os dados reais. A
 * randomizacao e modelada como colapso do historico num unico identificador
 * sintetico por dispositivo (o atacante perde a continuidade entre varreduras);
 * a supressao da PNL e modelada esvaziando os SSIDs citados.
 */
function cloneWith(
  store: CaptureStore,
  params: { randomizeMac: boolean; suppressPnl: boolean },
): CaptureStore {
  const clone = store.clone();

  if (params.suppressPnl) {
    for (const device of clone.devices.values()) {
      device.ssids.clear();
    }
    clone.ssidCounter.clear();
  }

  if (params.randomizeMac) {
    // Com MAC aleatorio por varredura, o atacante nao consegue mais unir as
    // observacoes de um mesmo aparelho pelo endereco; modelamos marcando todos
    // como randomizados e removendo o OUI (fabricante deixa de ser resoluvel).
    // O reagrupamento por fingerprint permanece possivel -- e e justamente o
    // que a simulacao deixa visivel quando so esta medida e aplicada.
    for (const device of clone.devices.values()) {
      device.isRandomized = true;
      device.oui = null;
    }
  }

  return clone;
}

/** Numeros-chave de uma captura, para comparar antes/depois. */
function metrics(
  store: CaptureStore,
  anonymizer: Representer,
): CountermeasureRow["metrics"] {
  const assessment = assess(store, anonymizer);
  return {
    devices_leaking_pnl: assessment.deviceInferences.filter(
      (d) => d.leaksPreferredNetworks).length,
    social_links: assessment.socialLinks.length,
    fingerprint_groups_defeating_randomization:
      assessment.fingerprintDefeatsRandomization.length,
    resolvable_vendors: store.observedOuis.size,
  };
}

/** Contramedidas simuladas, na ordem em que entram no relatorio. */
const COUNTERMEASURES: Array<{
  name: string;
  params: { randomizeMac: boolean; suppressPnl: boolean };
  description: string;
}> = [
  {
    name: "sem_defesa",
    params: { randomizeMac: false, suppressPnl: false },
    description: "Linha de base: dispositivo com MAC fixo e PNL ativa",
  },
  {
    name: "mac_randomization",
    params: { randomizeMac: true, suppressPnl: false },
    description: "Só randomização de MAC (iOS/Android atuais)",
  },
  {
    name: "null_probe_only",
    params: { randomizeMac: false, suppressPnl: true },
    description: "Só probe de varredura genérica, sem citar redes conhecidas",
  },
  {
    name: "mac_and_null",
    params: { randomizeMac: true, suppressPnl: true },
    description:
      "Randomização de MAC + supressão da PNL (estado da arte do cliente)",
  },
];

/**
 * Mede o efeito de cada contramedida sobre os vetores de inferencia.
 *
 * Para cada defesa, reexecuta a analise numa copia dos dados e devolve as
 * metricas resultantes. A leitura pretendida: comparar `mac_randomization`
 * com `mac_and_null` evidencia que suprimir a PNL, e nao trocar o MAC, e o
 * que efetivamente fecha o vetor dominante.
 */
export function simulateCountermeasures(
  store: CaptureStore,
  anonymizer: Representer,
): Array<Record<string, unknown>> {
  const rows: CountermeasureRow[] = [];
  for (const { name, params, description } of COUNTERMEASURES) {
    const variant = cloneWith(store, params);
    rows.push({
      countermeasure: name,
      description,
      metrics: metrics(variant, anonymizer),
    });
  }
  return rows;
}
