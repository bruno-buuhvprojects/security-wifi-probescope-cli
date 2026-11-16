// Relatorio e exportacao dos resultados da captura.
//
// Reune estatisticas da sessao, as inferencias de privacidade e a simulacao de
// contramedidas num unico relatorio, e grava o conjunto de dados em CSV ou JSON.
// Todo arquivo exportado carrega um bloco de proveniencia que registra o modo
// de anonimizacao aplicado -- de forma que o dado, se circular, denuncie se
// contem identificador em claro.

import { writeFileSync } from "node:fs";

import { assess } from "./inference.js";
import { scoreDevices, simulateCountermeasures } from "./defense.js";
import type { MacAnonymizer } from "./anonymize.js";
import { CaptureStore, utcNow } from "./models.js";
import {
  DeviceRowSchema,
  JsonExportSchema,
  SummarySchema,
  type DeviceRow,
  type Summary,
} from "./schemas.js";

/** Arredonda para uma casa decimal (equivale a round(x, 1) do Python). */
function round1(value: number): number {
  return Math.round(value * 10) / 10;
}

/** Arredonda para tres casas decimais (equivale a round(x, 3) do Python). */
function round3(value: number): number {
  return Math.round(value * 1000) / 1000;
}

/**
 * Monta o relatorio consolidado da sessao.
 *
 * O objeto montado tem chaves em snake_case identicas ao formato Python e e
 * validado contra `SummarySchema` antes de sair: qualquer divergencia de
 * contrato falha aqui, cedo, em vez de produzir um arquivo invalido.
 */
export function buildSummary(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
): Summary {
  store.finishedAt = store.finishedAt ?? utcNow();
  const totalDevices = store.devices.size;
  const randomized = store.randomizedCount;

  const assessment = assess(store, anonymizer);
  const countermeasures = simulateCountermeasures(store, anonymizer);
  const exposure = scoreDevices(store, anonymizer);

  const topSsids = store.mostCommonSsids(10);

  let devicesWithVendor = 0;
  for (const device of store.devices.values()) {
    if (device.vendor) {
      devicesWithVendor += 1;
    }
  }

  const durationSeconds = round1(
    (store.finishedAt.getTime() - store.startedAt.getTime()) / 1000,
  );

  const summary = {
    session: {
      started_at: store.startedAt.toISOString(),
      finished_at: store.finishedAt.toISOString(),
      duration_seconds: durationSeconds,
      provenance: anonymizer.provenance(),
    },
    totals: {
      frames_processed: store.totalFrames,
      unique_devices: totalDevices,
      randomized_mac_devices: randomized,
      randomized_mac_ratio: totalDevices
        ? round3(randomized / totalDevices)
        : 0.0,
      devices_with_vendor: devicesWithVendor,
      distinct_ssids: store.ssidCounter.size,
    },
    top_ssids: topSsids.map(([ssid, requests]) => ({ ssid, requests })),
    privacy_assessment: assessment.asDict(),
    exposure_ranking: exposure.map((e) => e.asDict()),
    countermeasure_simulation: countermeasures,
  };

  // Falha cedo se algum asDict()/metrica divergir do contrato serializado.
  return SummarySchema.parse(summary);
}

/** Imprime o relatorio no terminal, legivel para a demonstracao. */
export function printReport(summary: Record<string, unknown>): void {
  const data = summary as Summary;
  const totals = data.totals;
  const prov = data.session.provenance;

  console.log("\n" + "=".repeat(68));
  console.log("  RELATORIO DA CAPTURA");
  console.log("=".repeat(68));
  console.log(`  Duracao ............... ${data.session.duration_seconds} s`);
  console.log(`  Quadros processados ... ${totals.frames_processed}`);
  console.log(`  Dispositivos unicos ... ${totals.unique_devices}`);
  console.log(
    `  Com MAC randomizado ... ${totals.randomized_mac_devices} ` +
      `(${(totals.randomized_mac_ratio * 100).toFixed(1)}%)`,
  );
  console.log(`  SSIDs distintos ....... ${totals.distinct_ssids}`);
  console.log(
    `  Modo de anonimizacao .. ${prov.anonymization_mode}` +
      (prov.contains_plaintext_identifiers ? "  [CONTEM MAC EM CLARO]" : ""),
  );

  const privacy = data.privacy_assessment;
  console.log("\n" + "-".repeat(68));
  console.log("  O QUE FOI POSSIVEL INFERIR");
  console.log("-".repeat(68));
  console.log(
    `  Dispositivos que vazaram a lista de redes . ` +
      `${privacy.devices_leaking_pnl}`,
  );
  console.log(
    `  Vinculos sociais provaveis (SSID em comum)  ` +
      `${privacy.social_links.length}`,
  );
  console.log(
    `  Grupos onde o fingerprint venceu a ` +
      `randomizacao . ${privacy.fingerprint_defeats_randomization.length}`,
  );

  const links = privacy.social_links.slice(0, 3);
  if (links.length) {
    console.log("\n  Exemplos de vinculo entre dispositivos:");
    for (const link of links) {
      console.log(
        `    ${link.device_a} <-> ${link.device_b} ` +
          `via ${link.shared_networks.join(", ")}`,
      );
    }
  }

  console.log("\n" + "-".repeat(68));
  console.log("  EFEITO DAS CONTRAMEDIDAS (simulado sobre os mesmos dados)");
  console.log("-".repeat(68));
  console.log(
    "  " +
      "contramedida".padEnd(22) +
      "PNL".padStart(6) +
      "vinculos".padStart(10) +
      "fp-grupos".padStart(11) +
      "fabric.".padStart(9),
  );
  for (const row of data.countermeasure_simulation) {
    const m = row.metrics;
    console.log(
      "  " +
        row.countermeasure.padEnd(22) +
        String(m.devices_leaking_pnl).padStart(6) +
        String(m.social_links).padStart(10) +
        String(m.fingerprint_groups_defeating_randomization).padStart(11) +
        String(m.resolvable_vendors).padStart(9),
    );
  }
  console.log("=".repeat(68) + "\n");
}

/** Grava os dados capturados no formato pedido. */
export function exportResults(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
  path: string,
  fmt: "csv" | "json",
  summary?: Record<string, unknown>,
): void {
  if (fmt === "csv") {
    exportCsv(store, anonymizer, path);
  } else if (fmt === "json") {
    exportJson(store, anonymizer, path, summary);
  } else {
    throw new Error("Formato nao suportado: " + fmt);
  }
  console.log(`Resultados gravados em ${path}`);
}

/**
 * Converte os registros em linhas, aplicando o modo de anonimizacao.
 *
 * O identificador sai de `anonymizer.represent` -- o mesmo ponto usado no
 * console --, garantindo que arquivo e tela nunca divirjam sobre revelar ou nao
 * o MAC. Cada linha e validada contra `DeviceRowSchema`.
 */
function deviceRows(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
): DeviceRow[] {
  const rows: DeviceRow[] = [];
  for (const device of store.devices.values()) {
    const row = {
      device_id: anonymizer.represent(device.macAddress),
      first_seen: device.firstSeen.toISOString(),
      last_seen: device.lastSeen.toISOString(),
      frame_count: device.frameCount,
      is_randomized: device.isRandomized,
      oui: device.oui ?? "",
      vendor: device.vendor ?? "",
      ssids: [...device.ssids].sort().join(" | "),
      fingerprints: [...device.fingerprints].sort().join(" | "),
      channels: [...device.channels].sort((a, b) => a - b).join(","),
      rssi_max: device.rssiMax ?? "",
      rssi_mean: device.rssiMean ?? "",
    };
    rows.push(DeviceRowSchema.parse(row));
  }
  return rows;
}

/** Nomes das colunas do CSV, na ordem exata do formato exportado. */
const CSV_FIELDNAMES = [
  "device_id",
  "first_seen",
  "last_seen",
  "frame_count",
  "is_randomized",
  "oui",
  "vendor",
  "ssids",
  "fingerprints",
  "channels",
  "rssi_max",
  "rssi_mean",
] as const;

/**
 * Formata um campo no estilo QUOTE_MINIMAL do modulo csv do Python: envolve em
 * aspas duplas apenas se contiver virgula, aspas, CR ou LF, dobrando as aspas
 * internas.
 */
function csvField(value: unknown): string {
  const text = String(value);
  if (/[",\r\n]/.test(text)) {
    return '"' + text.replace(/"/g, '""') + '"';
  }
  return text;
}

function exportCsv(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
  path: string,
): void {
  const rows = deviceRows(store, anonymizer);
  const prov = anonymizer.provenance();

  // Cabecalho comentado registra a proveniencia tambem no CSV, que nao tem onde
  // guardar metadados estruturados.
  let out =
    `# anonymization_mode=${prov.anonymization_mode} ` +
    `contains_plaintext_identifiers=${prov.contains_plaintext_identifiers}\n`;

  out += CSV_FIELDNAMES.map(csvField).join(",") + "\r\n";
  for (const row of rows) {
    out +=
      CSV_FIELDNAMES.map((field) => csvField(row[field])).join(",") + "\r\n";
  }

  writeFileSync(path, out, "utf-8");
}

function exportJson(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
  path: string,
  summary?: Record<string, unknown>,
): void {
  const payload = {
    provenance: anonymizer.provenance(),
    generated_at: utcNow().toISOString(),
    summary,
    devices: deviceRows(store, anonymizer),
  };

  // Valida o payload inteiro antes de gravar; falha cedo se algo divergir.
  const validated = JsonExportSchema.parse(payload);
  writeFileSync(path, JSON.stringify(validated, null, 2), "utf-8");
}
