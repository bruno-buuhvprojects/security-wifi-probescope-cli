// Modelo de dados da captura.
//
// `ProbeObservation` e um quadro isolado ja interpretado; `DeviceRecord` e o
// acumulo de observacoes de um mesmo endereco; `CaptureStore` guarda o estado
// da sessao. O estado vive aqui, em objetos, e nao em variaveis globais, para
// que duas capturas possam coexistir no mesmo processo -- condicao necessaria
// para testar o agregador sem efeitos colaterais entre casos.

import type { MacClassification } from "./macaddr.js";
import type { ProbeFingerprint } from "./fingerprint.js";

/**
 * Horario corrente. Capturas sao comparadas entre si e com logs de outras
 * ferramentas; o Date do Node ja carrega o instante absoluto (epoch), que e o
 * necessario para ordenar e medir duracoes.
 */
export function utcNow(): Date {
  return new Date();
}

/** Um probe request interpretado. */
export class ProbeObservation {
  macAddress: string;
  ssid: string | null;
  rssi: number | null;
  channel: number | null;
  sequenceNumber: number | null;
  timestamp: Date;
  classification: MacClassification;
  fingerprint: ProbeFingerprint;

  constructor(init: {
    macAddress: string;
    ssid: string | null;
    rssi: number | null;
    channel: number | null;
    sequenceNumber: number | null;
    timestamp: Date;
    classification: MacClassification;
    fingerprint: ProbeFingerprint;
  }) {
    this.macAddress = init.macAddress;
    this.ssid = init.ssid;
    this.rssi = init.rssi;
    this.channel = init.channel;
    this.sequenceNumber = init.sequenceNumber;
    this.timestamp = init.timestamp;
    this.classification = init.classification;
    this.fingerprint = init.fingerprint;
  }

  /** Probe sem SSID: varredura generica, nao revela rede conhecida. */
  get isBroadcastProbe(): boolean {
    return !this.ssid;
  }
}

/** Tudo que foi observado de um mesmo endereco de origem. */
export class DeviceRecord {
  macAddress: string;
  firstSeen: Date;
  lastSeen: Date;
  isRandomized: boolean;
  oui: string | null;
  ssids: Set<string>;
  fingerprints: Set<string>;
  frameCount: number;
  rssiSamples: number[];
  channels: Set<number>;
  vendor: string | null;

  constructor(init: {
    macAddress: string;
    firstSeen: Date;
    lastSeen: Date;
    isRandomized: boolean;
    oui: string | null;
    ssids?: Set<string>;
    fingerprints?: Set<string>;
    frameCount?: number;
    rssiSamples?: number[];
    channels?: Set<number>;
    vendor?: string | null;
  }) {
    this.macAddress = init.macAddress;
    this.firstSeen = init.firstSeen;
    this.lastSeen = init.lastSeen;
    this.isRandomized = init.isRandomized;
    this.oui = init.oui;
    this.ssids = init.ssids ?? new Set<string>();
    this.fingerprints = init.fingerprints ?? new Set<string>();
    this.frameCount = init.frameCount ?? 0;
    this.rssiSamples = init.rssiSamples ?? [];
    this.channels = init.channels ?? new Set<number>();
    this.vendor = init.vendor ?? null;
  }

  /** Incorpora mais uma observacao ao registro. */
  update(obs: ProbeObservation): void {
    this.lastSeen = obs.timestamp;
    this.frameCount += 1;
    if (obs.ssid) {
      this.ssids.add(obs.ssid);
    }
    this.fingerprints.add(obs.fingerprint.digest);
    if (obs.rssi !== null) {
      this.rssiSamples.push(obs.rssi);
    }
    if (obs.channel !== null) {
      this.channels.add(obs.channel);
    }
  }

  /** Maior RSSI observado: melhor proxy de aproximacao fisica. */
  get rssiMax(): number | null {
    return this.rssiSamples.length ? Math.max(...this.rssiSamples) : null;
  }

  /** Media do RSSI, util para estimar distancia relativa. */
  get rssiMean(): number | null {
    if (!this.rssiSamples.length) {
      return null;
    }
    const sum = this.rssiSamples.reduce((acc, value) => acc + value, 0);
    return Math.round((sum / this.rssiSamples.length) * 10) / 10;
  }

  /** Janela entre a primeira e a ultima observacao, em segundos. */
  get durationSeconds(): number {
    return (this.lastSeen.getTime() - this.firstSeen.getTime()) / 1000;
  }

  /** Copia profunda do registro (Sets e arrays duplicados). */
  clone(): DeviceRecord {
    return new DeviceRecord({
      macAddress: this.macAddress,
      firstSeen: new Date(this.firstSeen.getTime()),
      lastSeen: new Date(this.lastSeen.getTime()),
      isRandomized: this.isRandomized,
      oui: this.oui,
      ssids: new Set(this.ssids),
      fingerprints: new Set(this.fingerprints),
      frameCount: this.frameCount,
      rssiSamples: [...this.rssiSamples],
      channels: new Set(this.channels),
      vendor: this.vendor,
    });
  }
}

/** Agrega observacoes por endereco e por assinatura de radio. */
export class CaptureStore {
  devices: Map<string, DeviceRecord>;
  totalFrames: number;
  /**
   * Assinatura de IEs -> enderecos que a apresentaram. Quando um mesmo aparelho
   * troca de MAC aleatorio, os varios enderecos caem aqui sob a mesma chave.
   */
  fingerprintGroups: Map<string, Set<string>>;
  ssidCounter: Map<string, number>;
  startedAt: Date;
  finishedAt: Date | null;

  constructor() {
    this.devices = new Map();
    this.totalFrames = 0;
    this.fingerprintGroups = new Map();
    this.ssidCounter = new Map();
    this.startedAt = utcNow();
    this.finishedAt = null;
  }

  /**
   * Registra uma observacao.
   *
   * Retorna o registro afetado e se ela trouxe informacao nova (endereco
   * inedito ou SSID inedito para aquele endereco), criterio usado para decidir
   * o que imprimir no console sem inundar a tela.
   */
  add(obs: ProbeObservation): [DeviceRecord, boolean] {
    this.totalFrames += 1;
    const mac = obs.macAddress;
    let record = this.devices.get(mac);
    let isNew = false;

    if (record === undefined) {
      record = new DeviceRecord({
        macAddress: mac,
        firstSeen: obs.timestamp,
        lastSeen: obs.timestamp,
        isRandomized: obs.classification.isRandomized,
        oui: obs.classification.oui,
      });
      this.devices.set(mac, record);
      isNew = true;
    } else if (obs.ssid && !record.ssids.has(obs.ssid)) {
      isNew = true;
    }

    record.update(obs);

    if (obs.ssid) {
      this.ssidCounter.set(obs.ssid, (this.ssidCounter.get(obs.ssid) ?? 0) + 1);
    }

    const digest = obs.fingerprint.digest;
    let group = this.fingerprintGroups.get(digest);
    if (group === undefined) {
      group = new Set<string>();
      this.fingerprintGroups.set(digest, group);
    }
    group.add(mac);

    return [record, isNew];
  }

  /** Quantos enderecos distintos eram localmente administrados. */
  get randomizedCount(): number {
    let count = 0;
    for (const device of this.devices.values()) {
      if (device.isRandomized) {
        count += 1;
      }
    }
    return count;
  }

  /** OUIs passiveis de resolucao de fabricante. */
  get observedOuis(): Set<string> {
    const ouis = new Set<string>();
    for (const device of this.devices.values()) {
      if (device.oui) {
        ouis.add(device.oui);
      }
    }
    return ouis;
  }

  /** Preenche o fabricante dos registros a partir do mapa de OUIs. */
  applyVendors(vendors: Record<string, string>): void {
    for (const device of this.devices.values()) {
      if (device.oui) {
        device.vendor = vendors[device.oui] ?? null;
      }
    }
  }

  /**
   * Replica `Counter.most_common`: ordena por contagem decrescente, com empates
   * resolvidos pela ordem de insercao (Map preserva a ordem; o sort de array e
   * estavel no V8). Retorna os `n` primeiros como pares `[ssid, count]`.
   */
  mostCommonSsids(n: number): Array<[string, number]> {
    const entries = [...this.ssidCounter.entries()];
    entries.sort((a, b) => b[1] - a[1]);
    return entries.slice(0, n);
  }

  /** Copia profunda da captura; a simulacao jamais altera os dados reais. */
  clone(): CaptureStore {
    const copy = new CaptureStore();
    copy.totalFrames = this.totalFrames;
    copy.startedAt = new Date(this.startedAt.getTime());
    copy.finishedAt = this.finishedAt !== null ? new Date(this.finishedAt.getTime()) : null;

    copy.devices = new Map();
    for (const [mac, device] of this.devices) {
      copy.devices.set(mac, device.clone());
    }

    copy.fingerprintGroups = new Map();
    for (const [digest, macs] of this.fingerprintGroups) {
      copy.fingerprintGroups.set(digest, new Set(macs));
    }

    copy.ssidCounter = new Map(this.ssidCounter);
    return copy;
  }
}
