// Inferencias de privacidade a partir dos dados capturados.
//
// Este modulo existe para responder a pergunta central do trabalho: uma vez de
// posse de probe requests, o que se consegue deduzir sobre as pessoas por tras
// dos dispositivos? Ele nao coleta nada de novo -- opera sobre o que ja esta no
// `CaptureStore` e explicita o alcance do dado.
//
// Cada inferencia abaixo e um vetor documentado na literatura de privacidade em
// Wi-Fi (entre outros, Cunche 2014 sobre a PNL; Vanhoef et al. 2016 sobre o
// limite da randomizacao de MAC). O objetivo e demonstrativo e defensivo:
// evidenciar o risco para justificar as contramedidas (ver defense.ts).

import { CaptureStore } from "./models.js";
import type {
  DeviceInferenceDto,
  DeviceLinkDto,
  FingerprintGroup,
  RecurringDevice,
  PrivacyAssessmentDto,
} from "./schemas.js";

/** Interface minima do anonimizador usada aqui: so a conversao para exibicao. */
interface Representer {
  represent(mac: string | null | undefined): string;
}

/**
 * SSIDs genericos demais para sugerir vinculo entre dois dispositivos.
 * Redes abertas de grandes redes de varejo ligam estranhos, nao conhecidos.
 */
export const COMMON_SSIDS: Set<string> = new Set([
  "", "guest", "wifi", "free wifi", "public", "internet",
  "xfinitywifi", "attwifi", "eduroam", "starbucks",
]);

/** O que se deduz de um unico dispositivo a partir da sua PNL. */
export class DeviceInference {
  deviceId: string;
  knownNetworks: string[];
  isRandomized: boolean;
  /** SSIDs raros o bastante para servirem de quase-identificador. */
  distinctiveNetworks: string[];

  constructor(init: {
    deviceId: string;
    knownNetworks: string[];
    isRandomized: boolean;
    distinctiveNetworks?: string[];
  }) {
    this.deviceId = init.deviceId;
    this.knownNetworks = init.knownNetworks;
    this.isRandomized = init.isRandomized;
    this.distinctiveNetworks = init.distinctiveNetworks ?? [];
  }

  /** O aparelho revelou a lista de redes a que costuma conectar. */
  get leaksPreferredNetworks(): boolean {
    return this.knownNetworks.length > 0;
  }

  asDict(): Record<string, unknown> {
    const dto: DeviceInferenceDto = {
      device_id: this.deviceId,
      known_networks: this.knownNetworks,
      is_randomized: this.isRandomized,
      distinctive_networks: this.distinctiveNetworks,
    };
    return dto;
  }
}

/** Vinculo provavel entre dois dispositivos por SSID compartilhado. */
export class DeviceLink {
  deviceA: string;
  deviceB: string;
  sharedNetworks: string[];

  constructor(init: {
    deviceA: string;
    deviceB: string;
    sharedNetworks: string[];
  }) {
    this.deviceA = init.deviceA;
    this.deviceB = init.deviceB;
    this.sharedNetworks = init.sharedNetworks;
  }

  /** Quanto mais redes distintas em comum, mais forte o vinculo. */
  get strength(): number {
    return this.sharedNetworks.length;
  }

  asDict(): Record<string, unknown> {
    const dto: DeviceLinkDto = {
      device_a: this.deviceA,
      device_b: this.deviceB,
      shared_networks: this.sharedNetworks,
    };
    return dto;
  }
}

/** Consolidacao das inferencias sobre uma captura. */
export class PrivacyAssessment {
  deviceInferences: DeviceInference[];
  socialLinks: DeviceLink[];
  fingerprintDefeatsRandomization: Array<Record<string, unknown>>;
  recurringDevices: Array<Record<string, unknown>>;

  constructor(init: {
    deviceInferences: DeviceInference[];
    socialLinks: DeviceLink[];
    fingerprintDefeatsRandomization: Array<Record<string, unknown>>;
    recurringDevices: Array<Record<string, unknown>>;
  }) {
    this.deviceInferences = init.deviceInferences;
    this.socialLinks = init.socialLinks;
    this.fingerprintDefeatsRandomization = init.fingerprintDefeatsRandomization;
    this.recurringDevices = init.recurringDevices;
  }

  asDict(): Record<string, unknown> {
    const dto: PrivacyAssessmentDto = {
      devices_leaking_pnl: this.deviceInferences.filter(
        (d) => d.leaksPreferredNetworks).length,
      device_inferences: this.deviceInferences.map(
        (d) => d.asDict() as DeviceInferenceDto),
      social_links: this.socialLinks.map((l) => l.asDict() as DeviceLinkDto),
      fingerprint_defeats_randomization:
        this.fingerprintDefeatsRandomization as FingerprintGroup[],
      recurring_devices: this.recurringDevices as RecurringDevice[],
    };
    return dto;
  }
}

/**
 * Filtra SSIDs que funcionam como quase-identificadores.
 *
 * Uma rede vista em muitos dispositivos (ex.: Wi-Fi de aeroporto) nao
 * distingue ninguem; uma rede domestica ou corporativa vista num punhado de
 * aparelhos aproxima-se de um identificador.
 */
export function distinctive(
  ssids: Set<string>,
  popularity: Map<string, number>,
): string[] {
  const result: string[] = [];
  for (const ssid of ssids) {
    if (COMMON_SSIDS.has(ssid.toLowerCase())) {
      continue;
    }
    // Visivel em no maximo 2 dispositivos: candidato a identificar o dono.
    if ((popularity.get(ssid) ?? 0) <= 2) {
      result.push(ssid);
    }
  }
  result.sort();
  return result;
}

/** Em quantos dispositivos distintos cada SSID aparece. */
export function devicePopularity(store: CaptureStore): Map<string, number> {
  const popularity = new Map<string, number>();
  for (const device of store.devices.values()) {
    for (const ssid of device.ssids) {
      popularity.set(ssid, (popularity.get(ssid) ?? 0) + 1);
    }
  }
  return popularity;
}

/**
 * Produz o conjunto de inferencias sobre a captura.
 *
 * `anonymizer` converte o MAC em identificador de exibicao, de modo que o
 * relatorio de privacidade respeite o mesmo modo (mascarado/revelado) do
 * resto do programa.
 */
export function assess(
  store: CaptureStore,
  anonymizer: Representer,
  recurringMinFrames = 20,
  recurringMinSeconds = 120.0,
): PrivacyAssessment {
  const popularity = devicePopularity(store);

  const deviceInferences = inferDevices(store, anonymizer, popularity);
  const socialLinks = inferSocialLinks(store, anonymizer, popularity);
  const fpTracking = inferFingerprintTracking(store, anonymizer);
  const recurring = inferRecurring(
    store, anonymizer, recurringMinFrames, recurringMinSeconds);

  return new PrivacyAssessment({
    deviceInferences,
    socialLinks,
    fingerprintDefeatsRandomization: fpTracking,
    recurringDevices: recurring,
  });
}

/** Para cada dispositivo, a PNL exposta e seus SSIDs distintivos. */
function inferDevices(
  store: CaptureStore,
  anonymizer: Representer,
  popularity: Map<string, number>,
): DeviceInference[] {
  const inferences: DeviceInference[] = [];
  for (const device of store.devices.values()) {
    if (device.ssids.size === 0) {
      continue;
    }
    inferences.push(new DeviceInference({
      deviceId: anonymizer.represent(device.macAddress),
      knownNetworks: [...device.ssids].sort(),
      isRandomized: device.isRandomized,
      distinctiveNetworks: distinctive(device.ssids, popularity),
    }));
  }
  // Quem vaza mais redes aparece primeiro: maior superficie de inferencia.
  inferences.sort((a, b) => b.knownNetworks.length - a.knownNetworks.length);
  return inferences;
}

/**
 * Liga dispositivos que compartilham redes nao triviais.
 *
 * Dois aparelhos que buscam a mesma rede domestica ou corporativa rara
 * provavelmente pertencem a pessoas que convivem -- colegas, familia,
 * coabitantes. Redes genericas sao ignoradas para nao ligar estranhos.
 */
function inferSocialLinks(
  store: CaptureStore,
  anonymizer: Representer,
  popularity: Map<string, number>,
): DeviceLink[] {
  const links: DeviceLink[] = [];

  const devices = [...store.devices.values()].filter((d) => d.ssids.size > 0);
  for (let i = 0; i < devices.length; i++) {
    for (let j = i + 1; j < devices.length; j++) {
      const devA = devices[i];
      const devB = devices[j];
      const distinctiveShared: string[] = [];
      for (const s of devA.ssids) {
        if (!devB.ssids.has(s)) {
          continue;
        }
        if (COMMON_SSIDS.has(s.toLowerCase())) {
          continue;
        }
        if ((popularity.get(s) ?? 0) <= 3) {
          distinctiveShared.push(s);
        }
      }
      if (distinctiveShared.length > 0) {
        links.push(new DeviceLink({
          deviceA: anonymizer.represent(devA.macAddress),
          deviceB: anonymizer.represent(devB.macAddress),
          sharedNetworks: distinctiveShared.sort(),
        }));
      }
    }
  }

  links.sort((a, b) => b.strength - a.strength);
  return links;
}

/**
 * Agrupa MACs distintos sob a mesma assinatura de radio.
 *
 * Quando um grupo de fingerprint reune varios enderecos e ao menos um deles
 * e aleatorio, ha indicio de que um unico aparelho trocou de MAC -- ou seja,
 * a randomizacao nao impediu o reagrupamento. E a demonstracao pratica de
 * que trocar o MAC, sozinho, nao garante anonimato.
 */
function inferFingerprintTracking(
  store: CaptureStore,
  anonymizer: Representer,
): Array<Record<string, unknown>> {
  const groups: FingerprintGroup[] = [];
  for (const [digest, macs] of store.fingerprintGroups) {
    if (macs.size < 2) {
      continue;
    }
    const records = [...macs].map((m) => store.devices.get(m)!);
    const hasRandom = records.some((r) => r.isRandomized);
    if (!hasRandom) {
      continue;
    }
    groups.push({
      fingerprint: digest,
      distinct_mac_count: macs.size,
      randomized_in_group: records.filter((r) => r.isRandomized).length,
      device_ids: records
        .map((r) => anonymizer.represent(r.macAddress))
        .sort(),
    });
  }
  groups.sort((a, b) => b.distinct_mac_count - a.distinct_mac_count);
  return groups;
}

/**
 * Dispositivos com presenca prolongada ou intensa na captura.
 *
 * Muitos quadros ao longo de uma janela ampla indicam permanencia -- base
 * de analytics de fluxo em varejo e de rastreamento de presenca.
 */
function inferRecurring(
  store: CaptureStore,
  anonymizer: Representer,
  minFrames: number,
  minSeconds: number,
): Array<Record<string, unknown>> {
  const recurring: RecurringDevice[] = [];
  for (const device of store.devices.values()) {
    if (device.frameCount >= minFrames
        || device.durationSeconds >= minSeconds) {
      recurring.push({
        device_id: anonymizer.represent(device.macAddress),
        frame_count: device.frameCount,
        duration_seconds: Math.round(device.durationSeconds * 10) / 10,
        rssi_max: device.rssiMax,
        is_randomized: device.isRandomized,
      });
    }
  }
  recurring.sort((a, b) => b.frame_count - a.frame_count);
  return recurring;
}
