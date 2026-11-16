// Interpretacao de quadros 802.11 probe request a partir de BYTES crus.
//
// O original em Python delegava ao Scapy. Aqui lemos o buffer diretamente: um
// cabecalho RadioTap opcional (little-endian), seguido do quadro de gerencia
// 802.11 (Dot11) e sua cadeia de Information Elements. O modulo nao conhece a
// camada de captura -- recebe o quadro pronto --, o que o mantem testavel com
// vetores sinteticos e sem hardware.
//
// Regra invariante: parseProbeRequest NUNCA lanca. Um quadro corrompido vira
// null e a captura segue; o callback de captura roda por quadro e nao pode ser
// derrubado por um pacote malformado.

import { buildFingerprint } from "./fingerprint.js";
import { classify } from "./macaddr.js";
import { ProbeObservation, utcNow } from "./models.js";

/** Element ID do campo SSID. */
const SSID_ELEMENT_ID = 0;

/**
 * Limite de elementos percorridos por quadro. Um quadro malformado pode
 * encadear elementos indefinidamente; o teto impede travar o laco de captura.
 */
const MAX_ELEMENTS = 64;

/**
 * Tabela de campos do RadioTap: bit do bitmap "present" -> [tamanho, alinhamento]
 * em bytes. O alinhamento e relativo ao inicio do cabecalho RadioTap (offset 0
 * do quadro), como manda a especificacao. Bits de controle 29 (reset de
 * namespace) e 31 (extensao) nao consomem dados e ficam fora da tabela; o bit 30
 * (vendor namespace) consome [6, 2].
 */
const RADIOTAP_FIELDS: Map<number, [number, number]> = new Map([
  [0, [8, 8]], // TSFT
  [1, [1, 1]], // Flags
  [2, [1, 1]], // Rate
  [3, [4, 2]], // Channel (freq u16 + flags u16)
  [4, [2, 2]], // FHSS
  [5, [1, 1]], // dBm_AntSignal (int8, com sinal)
  [6, [1, 1]], // dBm_AntNoise
  [7, [2, 2]], // Lock_Quality
  [8, [2, 2]], // TX_Attenuation
  [9, [2, 2]], // dB_TX_Attenuation
  [10, [1, 1]], // dBm_TX_Power (int8)
  [11, [1, 1]], // Antenna
  [12, [1, 1]], // dB_AntSignal
  [13, [1, 1]], // dB_AntNoise
  [14, [2, 2]], // RX_flags
  [15, [2, 2]], // TX_flags
  [16, [1, 1]],
  [17, [1, 1]],
  [18, [3, 1]], // MCS
  [19, [8, 4]], // A-MPDU
  [20, [12, 2]], // VHT
  [21, [12, 8]], // timestamp
  [22, [12, 2]], // HE
  [23, [12, 2]], // HE-MU
  [30, [6, 2]], // vendor namespace
]);

/** Bits de controle do bitmap "present" que nao consomem bytes de dados. */
const RADIOTAP_CONTROL_BITS = new Set([29, 31]);

/** Converte frequencia central (MHz) em numero de canal 802.11. */
export function frequencyToChannel(freq: number | null): number | null {
  if (!freq) {
    return null;
  }
  if (freq === 2484) {
    // canal 14, excecao da banda 2.4 GHz
    return 14;
  }
  if (freq >= 2412 && freq <= 2472) {
    return Math.trunc((freq - 2407) / 5);
  }
  if (freq >= 5000 && freq <= 5900) {
    return Math.trunc((freq - 5000) / 5);
  }
  if (freq >= 5955 && freq <= 7115) {
    // 6 GHz (Wi-Fi 6E)
    return Math.trunc((freq - 5950) / 5);
  }
  return null;
}

/** Resultado da leitura do cabecalho RadioTap. */
interface RadiotapInfo {
  /** Offset onde comeca o quadro Dot11. */
  dot11Off: number;
  rssi: number | null;
  channel: number | null;
}

/**
 * Le RSSI e canal do cabecalho RadioTap e localiza o inicio do quadro Dot11.
 *
 * A extracao de RSSI/canal e defensiva: ao topar com um bit desconhecido ou um
 * campo que ultrapasse os limites do cabecalho, aborta e devolve rssi/canal
 * nulos em vez de arriscar leitura desalinhada. Isso nao descarta o quadro -- o
 * quadro Dot11 ainda e interpretado a partir de dot11Off.
 */
function readRadiotap(frame: Buffer): RadiotapInfo {
  // Versao (frame[0], espera 0) e tamanho total do cabecalho.
  const rtLen = frame.readUInt16LE(2);
  const info: RadiotapInfo = { dot11Off: rtLen, rssi: null, channel: null };

  // Sem espaco para ao menos uma palavra "present": nada a extrair.
  if (frame.length < 8 || rtLen < 8 || rtLen > frame.length) {
    return info;
  }

  // Caminha as palavras "present": enquanto o bit 31 estiver setado, ha outra.
  const firstPresent = frame.readUInt32LE(4);
  let presentWords = 1;
  let presentOff = 4;
  while ((frame.readUInt32LE(presentOff) & 0x80000000) !== 0) {
    presentOff += 4;
    presentWords += 1;
    // Guarda contra palavras present que extrapolam o cabecalho declarado.
    if (presentOff + 4 > rtLen || presentOff + 4 > frame.length) {
      return info;
    }
  }

  // Os campos de dados comecam logo apos a ultima palavra present. So os bits da
  // PRIMEIRA palavra pertencem ao namespace padrao (onde vivem RSSI e canal), e
  // seus campos aparecem primeiro na regiao de dados -- por isso basta percorrer
  // a primeira palavra.
  let off = 4 + 4 * presentWords;

  for (let bit = 0; bit <= 30; bit++) {
    if ((firstPresent & (1 << bit)) === 0) {
      continue;
    }
    if (RADIOTAP_CONTROL_BITS.has(bit)) {
      continue;
    }

    const field = RADIOTAP_FIELDS.get(bit);
    if (field === undefined) {
      // Bit setado desconhecido: desalinharia tudo a frente. Aborta com seguranca.
      break;
    }

    const [size, align] = field;
    // Alinhamento relativo ao inicio do RadioTap (offset 0 do quadro).
    off = Math.ceil(off / align) * align;

    if (off + size > rtLen || off + size > frame.length) {
      // Campo ultrapassa o cabecalho: para por aqui, sem leitura invalida.
      break;
    }

    if (bit === 5) {
      // dBm_AntSignal: inteiro com sinal.
      info.rssi = frame.readInt8(off);
    } else if (bit === 3) {
      // Channel: frequencia u16 seguida de flags u16.
      info.channel = frequencyToChannel(frame.readUInt16LE(off));
    }

    off += size;
  }

  return info;
}

/**
 * Percorre a cadeia de Information Elements do corpo do quadro.
 *
 * Cada elemento e [id (1 byte), len (1 byte), payload (len bytes)]. O laco para
 * ao faltar bytes para o cabecalho ou para o payload declarado, e respeita o
 * teto MAX_ELEMENTS para nao travar em um quadro malformado.
 */
export function extractElements(body: Buffer): Array<[number, Buffer]> {
  const elements: Array<[number, Buffer]> = [];
  let p = 0;

  while (p + 2 <= body.length && elements.length < MAX_ELEMENTS) {
    const id = body[p];
    const len = body[p + 1];
    if (p + 2 + len > body.length) {
      break;
    }
    const payload = body.subarray(p + 2, p + 2 + len);
    elements.push([id, payload]);
    p += 2 + len;
  }

  return elements;
}

/**
 * Extrai o SSID, distinguindo ausencia (varredura generica) de nome vazio.
 *
 * SSID de comprimento zero -> null (probe de varredura). Caso contrario decodifica
 * como UTF-8 e remove caracteres de controle (equivalente ao str.isprintable do
 * Python: descarta codepoints < 0x20, 0x7f e a faixa 0x80..0x9f) para nao
 * corromper o terminal nem o CSV gerado. Se sobrar string vazia -> null.
 */
export function extractSsid(elements: Array<[number, Buffer]>): string | null {
  for (const [elementId, payload] of elements) {
    if (elementId !== SSID_ELEMENT_ID) {
      continue;
    }
    if (payload.length === 0) {
      return null;
    }
    const text = payload.toString("utf8");
    let cleaned = "";
    for (const ch of text) {
      const cp = ch.codePointAt(0)!;
      const isControl = cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f);
      if (!isControl) {
        cleaned += ch;
      }
    }
    return cleaned || null;
  }
  return null;
}

/**
 * Formata 6 bytes como endereco MAC "aa:bb:cc:dd:ee:ff" (hex minusculo).
 */
function formatMac(frame: Buffer, offset: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(frame[offset + i].toString(16).padStart(2, "0"));
  }
  return parts.join(":");
}

/**
 * Converte um quadro cru em observacao, ou null se nao for um probe request
 * valido ou se a leitura falhar. NUNCA lanca: todo erro de leitura vira null.
 *
 * @param frame  Quadro capturado (RadioTap opcional + Dot11).
 * @param opts.hasRadiotap  Se ha cabecalho RadioTap no inicio (default true).
 */
export function parseProbeRequest(
  frame: Buffer,
  opts?: { hasRadiotap?: boolean },
): ProbeObservation | null {
  const hasRadiotap = opts?.hasRadiotap ?? true;

  try {
    let dot11Off = 0;
    let rssi: number | null = null;
    let channel: number | null = null;

    if (hasRadiotap) {
      if (frame.length < 4 || frame[0] !== 0) {
        return null;
      }
      const rt = readRadiotap(frame);
      dot11Off = rt.dot11Off;
      rssi = rt.rssi;
      channel = rt.channel;
    }

    // O quadro de gerencia precisa de ao menos 24 bytes de cabecalho MAC.
    if (dot11Off + 24 > frame.length) {
      return null;
    }

    // Frame Control: type nos bits 2-3, subtype nos bits 4-7 do primeiro octeto.
    const fc0 = frame[dot11Off];
    const type = (fc0 >> 2) & 0x3;
    const subtype = (fc0 >> 4) & 0xf;
    // Probe request = management (type 0), subtype 4.
    if (type !== 0 || subtype !== 4) {
      return null;
    }

    // addr2 (endereco de origem) ocupa os bytes dot11Off+10 .. dot11Off+15.
    const addr2 = formatMac(frame, dot11Off + 10);
    const macAddress = addr2.trim().toLowerCase();
    const classification = classify(addr2);
    if (!classification.isValid) {
      return null;
    }

    // Sequence Control: 4 bits baixos sao o fragmento; os 12 altos, a sequencia.
    const sequenceControl = frame.readUInt16LE(dot11Off + 22);
    const sequenceNumber = sequenceControl >> 4;

    // Corpo com os Information Elements comeca apos o cabecalho de 24 bytes.
    const body = frame.subarray(dot11Off + 24);
    const elements = extractElements(body);

    return new ProbeObservation({
      macAddress,
      ssid: extractSsid(elements),
      rssi,
      channel,
      sequenceNumber,
      timestamp: utcNow(),
      classification,
      fingerprint: buildFingerprint(elements),
    });
  } catch {
    // Quadro corrompido: descartado sem derrubar a captura.
    return null;
  }
}
