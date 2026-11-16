#!/usr/bin/env node
// Interface de linha de comando do Wi-Fi Probe Request Sniffer.
//
// Orquestra as tres camadas -- captura, processamento e apresentacao -- e expoe
// os modos de operacao ao operador. Textos de ajuda e logs em portugues; flags e
// identificadores em ingles, convencao do projeto. As opcoes parseadas a mao sao
// validadas contra `CliOptionsSchema` (Zod), a mesma fonte de verdade dos demais
// contratos de dados.

import process from "node:process";

import { VERSION } from "./index.js";
import { AnonymizationMode, MacAnonymizer } from "./anonymize.js";
import type { AnonymizationMode as AnonymizationModeType } from "./anonymize.js";
import { VendorResolver } from "./macaddr.js";
import { CaptureStore, utcNow } from "./models.js";
import type { ProbeObservation } from "./models.js";
import { buildSummary, printReport, exportResults } from "./report.js";
import { CliOptionsSchema, type CliOptions } from "./schemas.js";

/** Prefixo dos logs, imitando o formato do logging do Python (HH:MM:SS NIVEL). */
function now(): string {
  const d = new Date();
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

function logInfo(message: string): void {
  console.error(`${now()} INFO ${message}`);
}

function logWarning(message: string): void {
  console.error(`${now()} WARNING ${message}`);
}

function logError(message: string): void {
  console.error(`${now()} ERROR ${message}`);
}

const PROG = "wifi-probescope";

const HELP_TEXT = `uso: ${PROG} [-h] [--version] (-i INTERFACE | -r ARQUIVO.pcap)
                    [-d DURATION] [--channels CHANNELS] [--no-hop] [--monitor]
                    [--write-pcap ARQUIVO.pcap] [--reveal] [--anon-salt ANON_SALT]
                    [-V] [--oui-db ARQUIVO] [-o OUTPUT] [-f {csv,json}] [-q]

Captura e analise de probe requests 802.11, com foco em demonstrar e mitigar
riscos de privacidade.

opcoes:
  -h, --help            mostra esta mensagem de ajuda e sai
  --version             mostra a versao e sai

fonte de dados:
  -i, --interface INTERFACE
                        interface sem fio em modo monitor (captura ao vivo)
  -r, --read ARQUIVO.pcap
                        le de um arquivo PCAP em vez de capturar ao vivo
                        (modo offline, reprodutivel)

captura ao vivo:
  -d, --duration DURATION
                        duracao da captura em segundos
  --channels CHANNELS   lista de canais para o salto, ex.: 1,6,11,36
  --no-hop              desativa o salto de canal (fixa no canal atual)
  --monitor             tenta habilitar/desabilitar o modo monitor
                        automaticamente via airmon-ng
  --write-pcap ARQUIVO.pcap
                        grava os quadros capturados para reproducao

privacidade:
  --reveal              EXIBE o MAC em claro, sem pseudonimizar. Use apenas em
                        laboratorio controlado, com dispositivos proprios ou
                        consentimento.
  --anon-salt ANON_SALT
                        salt fixo para pseudonimos correlacionaveis entre
                        sessoes (padrao: aleatorio por sessao)

fabricante:
  -V, --vendor-lookup   resolve fabricante por OUI apos a captura
  --oui-db ARQUIVO      base local de OUI (linhas 'OUI,Fabricante')

saida:
  -o, --output OUTPUT   arquivo de resultados
  -f, --format {csv,json}
                        formato do arquivo (padrao: json)
  -q, --quiet           suprime o log por quadro durante a captura
`;

/** Erro de uso da CLI, equivalente ao parser.error do argparse (sai com 2). */
class CliUsageError extends Error {}

/** Opcoes cruas coletadas do argv, antes da validacao Zod. */
interface RawOptions {
  interface?: string;
  read?: string;
  durationSeconds?: number;
  channels?: number[];
  noHop: boolean;
  monitor: boolean;
  writePcap?: string;
  reveal: boolean;
  anonSalt?: string;
  vendorLookup: boolean;
  ouiDb?: string;
  output?: string;
  format: "csv" | "json";
  quiet: boolean;
}

/** Resultado do parsing do argv: ou uma acao imediata, ou as opcoes cruas. */
type ParseResult =
  | { kind: "help" }
  | { kind: "version" }
  | { kind: "options"; options: RawOptions };

/**
 * Parser de argumentos manual (sem dependencia externa), fiel ao argparse do
 * Python. Lanca `CliUsageError` para erros de uso, que a `main` converte em
 * codigo de saida 2.
 */
function parseArgs(argv: string[]): ParseResult {
  const raw: RawOptions = {
    noHop: false,
    monitor: false,
    reveal: false,
    vendorLookup: false,
    format: "json",
    quiet: false,
  };

  /** Consome o proximo token como valor da flag `flag`. */
  const takeValue = (flag: string, i: number): [string, number] => {
    const next = argv[i + 1];
    if (next === undefined) {
      throw new CliUsageError(`argumento ${flag}: esperava um valor`);
    }
    return [next, i + 1];
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    // Suporta a forma "--flag=valor" alem de "--flag valor".
    let inlineValue: string | undefined;
    let flag = arg;
    if (arg.startsWith("--") && arg.includes("=")) {
      const eq = arg.indexOf("=");
      flag = arg.slice(0, eq);
      inlineValue = arg.slice(eq + 1);
    }

    const valueFor = (name: string): string => {
      if (inlineValue !== undefined) {
        return inlineValue;
      }
      const [value, newI] = takeValue(name, i);
      i = newI;
      return value;
    };

    switch (flag) {
      case "-h":
      case "--help":
        return { kind: "help" };
      case "--version":
        return { kind: "version" };
      case "-i":
      case "--interface":
        raw.interface = valueFor(flag);
        break;
      case "-r":
      case "--read":
        raw.read = valueFor(flag);
        break;
      case "-d":
      case "--duration": {
        const value = valueFor(flag);
        const parsed = Number(value);
        if (!Number.isInteger(parsed)) {
          throw new CliUsageError(
            `argumento -d/--duration: valor inteiro invalido: '${value}'`,
          );
        }
        raw.durationSeconds = parsed;
        break;
      }
      case "--channels": {
        const value = valueFor(flag);
        raw.channels = value
          .split(",")
          .map((c) => c.trim())
          .filter((c) => c.length > 0)
          .map((c) => {
            const n = Number(c);
            if (!Number.isInteger(n)) {
              throw new CliUsageError(
                `argumento --channels: valor inteiro invalido: '${c}'`,
              );
            }
            return n;
          });
        break;
      }
      case "--no-hop":
        raw.noHop = true;
        break;
      case "--monitor":
        raw.monitor = true;
        break;
      case "--write-pcap":
        raw.writePcap = valueFor(flag);
        break;
      case "--reveal":
        raw.reveal = true;
        break;
      case "--anon-salt":
        raw.anonSalt = valueFor(flag);
        break;
      case "-V":
      case "--vendor-lookup":
        raw.vendorLookup = true;
        break;
      case "--oui-db":
        raw.ouiDb = valueFor(flag);
        break;
      case "-o":
      case "--output":
        raw.output = valueFor(flag);
        break;
      case "-f":
      case "--format": {
        const value = valueFor(flag);
        if (value !== "csv" && value !== "json") {
          throw new CliUsageError(
            `argumento -f/--format: escolha invalida: '${value}' (escolha entre 'csv', 'json')`,
          );
        }
        raw.format = value;
        break;
      }
      case "-q":
      case "--quiet":
        raw.quiet = true;
        break;
      default:
        throw new CliUsageError(`argumento nao reconhecido: ${arg}`);
    }
  }

  return { kind: "options", options: raw };
}

/** Decide o modo de anonimizacao; o modo revelado emite um aviso explicito. */
function resolveMode(options: CliOptions): AnonymizationModeType {
  if (options.reveal) {
    logWarning(
      "MODO REVELADO ativo: o MAC sera exibido e gravado em CLARO. Use apenas " +
        "em ambiente controlado e autorizado.",
    );
    return AnonymizationMode.REVEAL;
  }
  return AnonymizationMode.MASKED;
}

/**
 * Cria o callback que registra e, se nao silenciado, imprime o quadro.
 *
 * Imprime apenas observacoes novas (endereco inedito ou SSID inedito para o
 * endereco), criterio devolvido por `store.add`, para nao inundar o terminal.
 */
function makeObserver(
  store: CaptureStore,
  anonymizer: MacAnonymizer,
  quiet: boolean,
): (observation: ProbeObservation) => void {
  return (observation: ProbeObservation): void => {
    const [, isNew] = store.add(observation);
    if (quiet || !isNew) {
      return;
    }
    const ident = anonymizer.represent(observation.macAddress);
    const ssid = observation.ssid ? `"${observation.ssid}"` : "[varredura]";
    const rssi = observation.rssi !== null ? `${observation.rssi} dBm` : "N/A";
    const tag = observation.classification.isRandomized ? "rand" : "fixo";
    const ts = observation.timestamp;
    const hhmmss =
      String(ts.getHours()).padStart(2, "0") +
      ":" +
      String(ts.getMinutes()).padStart(2, "0") +
      ":" +
      String(ts.getSeconds()).padStart(2, "0");
    console.log(
      `[${hhmmss}] ${ident} (${tag}) | SSID: ${ssid} | RSSI: ${rssi} | ` +
        `FP: ${observation.fingerprint.digest}`,
    );
  };
}

/** Modo offline: le o PCAP e alimenta o observer. */
async function runOffline(
  options: CliOptions,
  store: CaptureStore,
  anonymizer: MacAnonymizer,
): Promise<number> {
  const { readPcap } = await import("./capture.js");
  const path = options.read as string;

  logInfo(`Lendo de ${path}`);
  const observe = makeObserver(store, anonymizer, options.quiet);
  try {
    for (const observation of readPcap(path)) {
      observe(observation);
    }
  } catch (exc) {
    if ((exc as NodeJS.ErrnoException).code === "ENOENT") {
      logError(`Arquivo PCAP não encontrado: ${path}`);
      return 1;
    }
    throw exc;
  }
  return 0;
}

/** Modo live: prepara a interface, captura e trata sinais e permissoes. */
async function runLive(
  options: CliOptions,
  store: CaptureStore,
  anonymizer: MacAnonymizer,
): Promise<number> {
  const {
    captureLive,
    disableMonitorMode,
    enableMonitorMode,
    MonitorModeError,
  } = await import("./capture.js");

  const iface = options.interface as string;
  const shouldStop = { flag: false };

  const handleSignal = (): void => {
    logInfo("Encerrando captura...");
    shouldStop.flag = true;
  };
  process.on("SIGINT", handleSignal);
  process.on("SIGTERM", handleSignal);

  let monitorIface = iface;
  if (options.monitor) {
    try {
      monitorIface = enableMonitorMode(iface);
    } catch (exc) {
      if (exc instanceof MonitorModeError) {
        logError(exc.message);
        return 1;
      }
      throw exc;
    }
  }

  let channels: number[] | undefined;
  if (options.noHop) {
    channels = [0]; // forca canal unico: o hopper se desativa sozinho
  } else if (options.channels) {
    channels = options.channels;
  }

  const observe = makeObserver(store, anonymizer, options.quiet);
  logInfo(`Capturando em ${monitorIface} — Ctrl+C para parar`);
  try {
    await captureLive({
      interface: monitorIface,
      onObservation: observe,
      durationSeconds: options.durationSeconds,
      channels,
      stopFlag: () => shouldStop.flag,
      pcapPath: options.writePcap,
    });
  } catch (exc) {
    const code = (exc as NodeJS.ErrnoException).code;
    if (code === "EACCES" || code === "EPERM") {
      logError(
        "Permissão negada. A captura ao vivo exige privilégios de root.",
      );
      return 1;
    }
    throw exc;
  } finally {
    if (options.monitor) {
      disableMonitorMode(monitorIface);
    }
  }
  return 0;
}

/** Ponto de entrada assincrono; devolve o codigo de saida do processo. */
export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  let parsed: ParseResult;
  try {
    parsed = parseArgs(argv);
  } catch (exc) {
    if (exc instanceof CliUsageError) {
      console.error(`${PROG}: erro: ${exc.message}`);
      return 2;
    }
    throw exc;
  }

  if (parsed.kind === "help") {
    console.log(HELP_TEXT);
    return 0;
  }
  if (parsed.kind === "version") {
    console.log(`${PROG} ${VERSION}`);
    return 0;
  }

  // Valida as opcoes ja parseadas contra o contrato Zop unico.
  let options: CliOptions;
  try {
    options = CliOptionsSchema.parse(parsed.options);
  } catch (exc) {
    console.error(`${PROG}: erro: opcoes invalidas: ${String(exc)}`);
    return 2;
  }

  if (!options.interface && !options.read) {
    console.error(
      `${PROG}: erro: informe uma interface (-i) ou um arquivo PCAP (-r)`,
    );
    return 2;
  }
  if (options.interface && options.read) {
    console.error(`${PROG}: erro: use -i ou -r, não os dois`);
    return 2;
  }

  const mode = resolveMode(options);
  const anonymizer = new MacAnonymizer({ mode, salt: options.anonSalt ?? null });
  const store = new CaptureStore();

  const status = options.read
    ? await runOffline(options, store, anonymizer)
    : await runLive(options, store, anonymizer);
  if (status !== 0) {
    return status;
  }

  store.finishedAt = utcNow();

  // Resolucao de fabricante so depois da captura, sobre os OUIs distintos --
  // fora do caminho critico, sem descartar quadros por I/O de rede.
  if (options.vendorLookup || options.ouiDb) {
    const resolver = new VendorResolver({
      enabled: options.vendorLookup,
      localDb: options.ouiDb,
    });
    store.applyVendors(await resolver.resolveAll(store.observedOuis));
  }

  const summary = buildSummary(store, anonymizer);
  printReport(summary);

  if (options.output) {
    exportResults(store, anonymizer, options.output, options.format, summary);
  }

  return 0;
}

// Executa apenas quando chamado como script (nao em import nos testes).
main().then((code) => {
  process.exitCode = code;
});
