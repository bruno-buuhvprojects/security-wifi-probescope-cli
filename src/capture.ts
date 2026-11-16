// Camada de captura: radio ao vivo e leitura de arquivos PCAP.
//
// Concentra tudo que depende de hardware, privilegio ou do addon nativo "cap",
// para que o restante do pacote permaneca testavel offline. Oferece dois
// caminhos equivalentes do ponto de vista da analise:
//
//   captureLive  captura da interface em modo monitor, com salto de canal;
//   readPcap     le um arquivo ".pcap" previamente gravado.
//
// O modo offline e o que torna a demonstracao reprodutivel: a mesma captura
// roda em qualquer maquina, sem adaptador nem root. Por isso readPcap e escrito
// so com "node:fs" e nao depende do "cap".

import {
  openSync,
  writeSync,
  closeSync,
  readFileSync,
} from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

import type { ProbeObservation } from "./models.js";
import { parseProbeRequest } from "./parsing.js";

// require sincrono para carregar o addon nativo "cap" fora de um contexto async
// (enableMonitorMode e setChannel sao sincronos por contrato). Se o addon nao
// estiver compilado, cada uso trata a ausencia graciosamente.
const requireNative = createRequire(import.meta.url);

/**
 * Canais 2.4 GHz nao sobrepostos mais um conjunto comum de 5 GHz. Cobrir so os
 * nao sobrepostos em 2.4 GHz evita gastar tempo em canais redundantes.
 */
export const DEFAULT_CHANNELS: number[] = [1, 6, 11, 36, 40, 44, 48];

/**
 * Tempo em cada canal durante o salto, em segundos. Curto demais perde quadros;
 * longo demais cega os outros canais. ~250 ms e um compromisso usual.
 */
export const DWELL_SECONDS = 0.25;

/** Falha ao preparar a interface para captura. */
export class MonitorModeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MonitorModeError";
  }
}

/** Mensagem unica para a ausencia do addon nativo de captura ao vivo. */
const CAP_MISSING =
  "Captura ao vivo requer o pacote nativo 'cap' (libpcap/Npcap). " +
  "Instale e rode 'npm install', ou use -r para ler um .pcap.";

/**
 * Ajusta o canal da interface via `iw`.
 *
 * Retorna `false` em vez de lancar: durante o salto, um canal que o adaptador
 * nao suporta (ou a ausencia do `iw` no Windows) deve ser apenas pulado, nao
 * interromper a captura. Os argumentos vao como lista, sem shell, de modo que
 * um nome de interface inesperado nao possa ser interpretado como comando.
 */
export function setChannel(iface: string, channel: number): boolean {
  try {
    execFileSync("iw", ["dev", iface, "set", "channel", String(channel)], {
      timeout: 5000,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Alterna o canal da interface em um timer dedicado.
 *
 * Sem salto, a captura enxerga um unico canal e perde a maioria dos
 * dispositivos, que se espalham pela banda. O timer e controlado por start/stop
 * para encerrar de forma limpa junto da captura.
 */
class ChannelHopper {
  private readonly iface: string;
  private readonly channels: number[];
  private readonly dwell: number;
  private index = 0;
  private timer: NodeJS.Timeout | null = null;

  constructor(iface: string, channels?: number[], dwell: number = DWELL_SECONDS) {
    this.iface = iface;
    this.channels = channels && channels.length > 0 ? channels : DEFAULT_CHANNELS;
    this.dwell = dwell;
  }

  start(): void {
    // Canal unico: nao ha para onde saltar.
    if (this.channels.length <= 1) {
      return;
    }
    const hop = (): void => {
      const channel = this.channels[this.index % this.channels.length];
      setChannel(this.iface, channel);
      this.index += 1;
    };
    hop();
    this.timer = setInterval(hop, this.dwell * 1000);
  }

  stop(): void {
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}

/** Lista os nomes de interface conhecidos pelo addon "cap", se disponivel. */
function listInterfaces(): Set<string> {
  try {
    const cap = requireNative("cap");
    const Cap = cap.Cap ?? cap.default?.Cap;
    const devices: Array<{ name?: string }> = Cap?.deviceList?.() ?? [];
    const names = new Set<string>();
    for (const device of devices) {
      if (device.name) {
        names.add(device.name);
      }
    }
    return names;
  } catch {
    // Addon ausente ou enumeracao indisponivel: conjunto vazio nao bloqueia.
    return new Set<string>();
  }
}

function interfaceExists(iface: string): boolean {
  const interfaces = listInterfaces();
  // Conjunto vazio: nao foi possivel enumerar; nao bloqueia a tentativa.
  return interfaces.size === 0 || interfaces.has(iface);
}

/** Pausa sincrona (bloqueante) de `ms` milissegundos, sem dependencias. */
function sleepSync(ms: number): void {
  const shared = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(shared, 0, 0, ms);
}

/**
 * Coloca a interface em modo monitor e retorna o nome efetivo dela.
 *
 * O `airmon-ng` frequentemente renomeia a interface (`wlan0` -> `wlan0mon`).
 * Capturar no nome antigo, que ja nao existe, significa nao ver trafego algum;
 * por isso a lista de interfaces e relida apos o comando e o novo nome e
 * devolvido ao chamador. Em Windows essas ferramentas nao existem: o comando
 * ausente vira um `MonitorModeError` claro, sem quebrar o processo.
 */
export function enableMonitorMode(iface: string): string {
  if (!interfaceExists(iface)) {
    throw new MonitorModeError(`Interface '${iface}' nao encontrada`);
  }

  const before = listInterfaces();
  try {
    execFileSync("airmon-ng", ["start", iface], {
      timeout: 30000,
      stdio: "ignore",
    });
  } catch (exc) {
    if ((exc as NodeJS.ErrnoException).code === "ENOENT") {
      throw new MonitorModeError("airmon-ng nao esta instalado");
    }
    throw new MonitorModeError(`airmon-ng falhou: ${(exc as Error).message}`);
  }

  sleepSync(1000);
  const after = listInterfaces();

  // Nome convencional ou interface nova que surgiu apos o comando.
  for (const candidate of [`${iface}mon`, `mon${iface}`]) {
    if (after.has(candidate)) {
      return candidate;
    }
  }
  for (const name of after) {
    if (!before.has(name)) {
      return name;
    }
  }
  return iface;
}

/** Devolve a interface ao modo gerenciado. Falhas apenas sao registradas. */
export function disableMonitorMode(iface: string): void {
  try {
    execFileSync("airmon-ng", ["stop", iface], {
      timeout: 30000,
      stdio: "ignore",
    });
  } catch (exc) {
    console.warn(
      `Falha ao desabilitar modo monitor em ${iface}: ${(exc as Error).message}`,
    );
  }
}

/**
 * Escritor .pcap classico minimo: cabecalho global (magic 0xa1b2c3d4, versao
 * 2.4, snaplen 65535, linktype 127 = radiotap) e, por quadro, o header de 16
 * bytes seguido dos bytes crus. Guarda a evidencia da demonstracao ao vivo.
 */
class PcapWriter {
  private fd: number;

  constructor(path: string, linktype = 127) {
    this.fd = openSync(path, "w");
    const header = Buffer.alloc(24);
    // Todos os campos em little-endian: o magic 0xa1b2c3d4 sinaliza LE ao leitor.
    header.writeUInt32LE(0xa1b2c3d4, 0); // magic
    header.writeUInt16LE(2, 4); // versao major
    header.writeUInt16LE(4, 6); // versao minor
    header.writeInt32LE(0, 8); // thiszone
    header.writeUInt32LE(0, 12); // sigfigs
    header.writeUInt32LE(65535, 16); // snaplen
    header.writeUInt32LE(linktype, 20); // linktype
    writeSync(this.fd, header);
  }

  writeFrame(frame: Buffer): void {
    const now = Date.now();
    const header = Buffer.alloc(16);
    header.writeUInt32LE(Math.floor(now / 1000), 0); // ts_sec
    header.writeUInt32LE((now % 1000) * 1000, 4); // ts_usec
    header.writeUInt32LE(frame.length, 8); // incl_len
    header.writeUInt32LE(frame.length, 12); // orig_len
    writeSync(this.fd, header);
    writeSync(this.fd, frame);
  }

  close(): void {
    try {
      closeSync(this.fd);
    } catch {
      // ja fechado ou descritor invalido: nada a fazer.
    }
  }
}

/** Magics conhecidos do PCAP classico, lidos como uint32 little-endian. */
const PCAP_MAGICS: Record<number, { le: boolean }> = {
  0xa1b2c3d4: { le: true }, // microssegundos, ordem do gravador == LE
  0xa1b23c4d: { le: true }, // nanossegundos
  0xa1b234cd: { le: true }, // variante de nanossegundos
  0xd4c3b2a1: { le: false }, // microssegundos, invertido -> ler BE
  0x4d3cb2a1: { le: false }, // nanossegundos invertido
  0xcd34b2a1: { le: false }, // variante de nanossegundos invertida
};

const PCAPNG_MAGIC = 0x0a0d0d0a;

const LINKTYPE_IEEE802_11 = 105; // 802.11 cru, sem radiotap
const LINKTYPE_IEEE802_11_RADIO = 127; // 802.11 com cabecalho radiotap

/** Mapeia o link-layer type para a presenca (ou nao) do cabecalho radiotap. */
function linktypeToHasRadiotap(linktype: number): boolean {
  if (linktype === LINKTYPE_IEEE802_11_RADIO) {
    return true;
  }
  if (linktype === LINKTYPE_IEEE802_11) {
    return false;
  }
  throw new Error(
    `Link-layer type ${linktype} nao suportado (esperado 127 = radiotap ou 105 = 802.11 cru).`,
  );
}

/**
 * Itera as observacoes de probe request contidas em um arquivo de captura.
 *
 * Detecta o formato pelo magic dos primeiros bytes e delega: PCAP classico
 * (0xa1b2c3d4 e variantes) ou PCAP Next Generation (.pcapng, bloco SHB
 * 0x0a0d0d0a). Gera as observacoes uma a uma para suportar capturas grandes.
 * Se o arquivo nao existe, o ENOENT do `readFileSync` se propaga (a CLI trata).
 */
export function* readPcap(path: string): Generator<ProbeObservation> {
  const buf = readFileSync(path);
  if (buf.length < 4) {
    throw new Error("Arquivo de captura truncado: sem magic reconhecivel.");
  }
  // O magic e sempre lido como LE; o valor resultante revela formato e ordem.
  const magic = buf.readUInt32LE(0);
  if (magic === PCAPNG_MAGIC) {
    yield* readPcapng(buf);
    return;
  }
  yield* readClassicPcap(buf);
}

/**
 * Leitor do PCAP classico: cabecalho global de 24 bytes e, por quadro, o header
 * de registro de 16 bytes seguido dos bytes crus. Determina a endianness pelo
 * magic e le TODOS os campos (inclusive linktype) com essa ordem.
 */
function* readClassicPcap(buf: Buffer): Generator<ProbeObservation> {
  if (buf.length < 24) {
    throw new Error("Arquivo .pcap truncado: cabecalho global incompleto.");
  }
  const magic = buf.readUInt32LE(0);
  const variant = PCAP_MAGICS[magic];
  if (!variant) {
    throw new Error(
      `Formato nao reconhecido: magic 0x${magic.toString(16).padStart(8, "0")} nao e um PCAP classico nem .pcapng.`,
    );
  }
  const le = variant.le;

  const readU32 = (offset: number): number =>
    le ? buf.readUInt32LE(offset) : buf.readUInt32BE(offset);

  const hasRadiotap = linktypeToHasRadiotap(readU32(20));

  let offset = 24;
  while (offset + 16 <= buf.length) {
    const inclLen = readU32(offset + 8);
    offset += 16;
    // Registro truncado ou comprimento absurdo: encerra sem quebrar.
    if (offset + inclLen > buf.length) {
      break;
    }
    const data = buf.subarray(offset, offset + inclLen);
    offset += inclLen;

    const observation = parseProbeRequest(data, { hasRadiotap });
    if (observation !== null) {
      yield observation;
    }
  }
}

// Tipos de bloco do pcapng que nos interessam (lidos na endianness da secao).
const PCAPNG_BLOCK_IDB = 0x00000001; // Interface Description Block
const PCAPNG_BLOCK_PACKET = 0x00000002; // Packet Block (obsoleto)
const PCAPNG_BLOCK_SPB = 0x00000003; // Simple Packet Block
const PCAPNG_BLOCK_EPB = 0x00000006; // Enhanced Packet Block
const PCAPNG_BYTE_ORDER_MAGIC = 0x1a2b3c4d; // no Section Header Block

/**
 * Leitor do PCAP Next Generation (.pcapng).
 *
 * O arquivo e uma sequencia de blocos no formato (type, total_length, corpo,
 * total_length). A ordem de bytes vem do "byte-order magic" do Section Header
 * Block; cada Interface Description Block acrescenta um link-layer type, e cada
 * bloco de pacote (Enhanced, Simple ou o Packet obsoleto) referencia uma
 * interface, de onde sai a presenca do radiotap. Avancamos sempre pelo
 * total_length do bloco, entao as opcoes e o padding sao ignorados sem precisar
 * interpreta-los.
 */
function* readPcapng(buf: Buffer): Generator<ProbeObservation> {
  if (buf.length < 12) {
    throw new Error("Arquivo .pcapng truncado: Section Header Block incompleto.");
  }
  // A endianness e descoberta pelo magic do primeiro SHB (offset 8 do bloco).
  let le: boolean;
  if (buf.readUInt32LE(8) === PCAPNG_BYTE_ORDER_MAGIC) {
    le = true;
  } else if (buf.readUInt32BE(8) === PCAPNG_BYTE_ORDER_MAGIC) {
    le = false;
  } else {
    throw new Error("Arquivo .pcapng invalido: byte-order magic ausente no SHB.");
  }

  const u16 = (o: number): number => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = (o: number): number => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));

  // link-layer type por interface, na ordem em que os IDB aparecem.
  const interfaceLinktypes: number[] = [];

  let offset = 0;
  while (offset + 12 <= buf.length) {
    const blockType = u32(offset);
    const totalLen = u32(offset + 4);
    // Comprimento invalido: encerra sem quebrar (arquivo corrompido/truncado).
    if (totalLen < 12 || totalLen % 4 !== 0 || offset + totalLen > buf.length) {
      break;
    }
    const body = offset + 8; // inicio do corpo do bloco

    if (blockType === PCAPNG_BLOCK_IDB) {
      // corpo: LinkType (u16), Reserved (u16), SnapLen (u32), opcoes...
      interfaceLinktypes.push(u16(body));
    } else if (blockType === PCAPNG_BLOCK_EPB) {
      // corpo: Interface ID (u32), ts high (u32), ts low (u32),
      //        Captured Len (u32), Original Len (u32), dados...
      const available = Math.max(0, totalLen - 32);
      const capturedLen = Math.min(u32(body + 12), available);
      yield* emitFrame(buf, body + 20, capturedLen, interfaceLinktypes[u32(body)]);
    } else if (blockType === PCAPNG_BLOCK_SPB) {
      // corpo: Original Len (u32), dados... (sempre referente a interface 0)
      const available = Math.max(0, totalLen - 16);
      const capturedLen = Math.min(u32(body), available);
      yield* emitFrame(buf, body + 4, capturedLen, interfaceLinktypes[0]);
    } else if (blockType === PCAPNG_BLOCK_PACKET) {
      // Packet Block obsoleto: Interface ID (u16), Drops (u16), ts high (u32),
      // ts low (u32), Captured Len (u32), Original Len (u32), dados...
      const available = Math.max(0, totalLen - 32);
      const capturedLen = Math.min(u32(body + 12), available);
      yield* emitFrame(buf, body + 20, capturedLen, interfaceLinktypes[u16(body)]);
    }
    // Section Header Block (nova secao) e demais tipos: so avancamos.

    offset += totalLen;
  }
}

/**
 * Interpreta um recorte de quadro de um pcapng e gera a observacao, se for probe
 * request. Ignora o quadro quando a interface referenciada e desconhecida ou o
 * link-layer type nao e de 802.11 — nesses casos nao da para dizer se ha
 * radiotap, entao pular e melhor do que abortar o arquivo inteiro.
 */
function* emitFrame(
  buf: Buffer,
  start: number,
  length: number,
  linktype: number | undefined,
): Generator<ProbeObservation> {
  if (linktype === undefined || length <= 0 || start + length > buf.length) {
    return;
  }
  let hasRadiotap: boolean;
  try {
    hasRadiotap = linktypeToHasRadiotap(linktype);
  } catch {
    return; // interface nao-802.11 na mesma captura: ignora so este quadro.
  }
  const data = buf.subarray(start, start + length);
  const observation = parseProbeRequest(data, { hasRadiotap });
  if (observation !== null) {
    yield observation;
  }
}

/** Opcoes de captura ao vivo. */
export interface CaptureLiveOptions {
  interface: string;
  onObservation: (o: ProbeObservation) => void;
  durationSeconds?: number;
  channels?: number[];
  stopFlag?: () => boolean;
  pcapPath?: string;
}

/**
 * Captura probe requests ao vivo, com salto de canal e PCAP opcionais.
 *
 * O addon nativo "cap" so e importado aqui, de forma dinamica e tipada como
 * `any`, para que o `tsc` (e todo o caminho offline/testes) compile e rode sem
 * ele. `onObservation` recebe cada quadro ja interpretado; `pcapPath`, se
 * informado, grava os quadros brutos para reproducao posterior.
 */
export async function captureLive(opts: CaptureLiveOptions): Promise<void> {
  let cap: any;
  try {
    cap = await import("cap");
  } catch {
    throw new Error(CAP_MISSING);
  }
  const Cap = cap.Cap ?? cap.default?.Cap;
  const decoders = cap.decoders ?? cap.default?.decoders;
  if (!Cap) {
    throw new Error(CAP_MISSING);
  }
  // decoders fica disponivel para extensoes futuras (ex.: inspecao de linkType).
  void decoders;

  const session = new Cap();
  // Resolve o device a partir do nome logico quando o "cap" oferece o helper.
  const device: string = Cap.findDevice?.(opts.interface) ?? opts.interface;

  // Filtro BPF: so quadros de gerencia do subtipo probe request, reduzindo o
  // volume entregue ao JavaScript.
  const filter = "type mgt subtype probe-req";
  const bufSize = 10 * 1024 * 1024; // folga generosa para rajadas
  const buffer = Buffer.alloc(65535);

  const linkType: string = session.open(device, filter, bufSize, buffer);
  try {
    session.setMinBytes?.(0);
  } catch {
    // Nem toda plataforma expoe setMinBytes; seguir sem ele e seguro.
  }

  // O linkType informado pelo Cap decide a presenca do cabecalho radiotap.
  const hasRadiotap = linkType === "IEEE802_11_RADIO";

  const writer = opts.pcapPath
    ? new PcapWriter(opts.pcapPath, hasRadiotap ? LINKTYPE_IEEE802_11_RADIO : LINKTYPE_IEEE802_11)
    : null;
  const hopper = new ChannelHopper(opts.interface, opts.channels);

  return new Promise<void>((resolve) => {
    let finished = false;
    let durationTimer: NodeJS.Timeout | null = null;
    let stopTimer: NodeJS.Timeout | null = null;

    const cleanup = (): void => {
      if (finished) {
        return;
      }
      finished = true;
      if (durationTimer !== null) {
        clearTimeout(durationTimer);
      }
      if (stopTimer !== null) {
        clearInterval(stopTimer);
      }
      hopper.stop();
      try {
        session.close();
      } catch {
        // sessao ja encerrada: nada a fazer.
      }
      if (writer !== null) {
        writer.close();
      }
      resolve();
    };

    session.on("packet", (nbytes: number) => {
      const frame = buffer.subarray(0, nbytes);
      const observation = parseProbeRequest(frame, { hasRadiotap });
      if (observation === null) {
        return;
      }
      if (writer !== null) {
        // Copia o recorte antes de gravar: o buffer de captura e reutilizado.
        writer.writeFrame(Buffer.from(frame));
      }
      opts.onObservation(observation);
    });

    hopper.start();

    if (opts.durationSeconds) {
      durationTimer = setTimeout(cleanup, opts.durationSeconds * 1000);
    }
    if (opts.stopFlag) {
      const stopFlag = opts.stopFlag;
      stopTimer = setInterval(() => {
        if (stopFlag()) {
          cleanup();
        }
      }, 200);
    }
  });
}
