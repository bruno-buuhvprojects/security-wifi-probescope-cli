#!/usr/bin/env node
// Gera um PCAP sintetico de probe requests para demonstracao offline.
//
// Porte do antigo tools/make_demo_pcap.py (que usava Scapy): aqui montamos os
// bytes do quadro a mao (RadioTap + Dot11 + Information Elements), sem Python nem
// dependencia nativa. O cenario exercita todos os vetores de inferencia e roda
// identico em qualquer maquina, sem adaptador nem root:
//
//   - um aparelho com MAC fixo que vaza uma PNL rica (vitima classica);
//   - dois aparelhos que compartilham uma rede domestica rara (vinculo social);
//   - um aparelho que troca de MAC aleatorio mantendo os mesmos IEs
//     (randomizacao derrotada por fingerprint);
//   - ruido de probes de varredura generica (sem SSID).
//
// Nenhum dado e real: MACs de documentacao/aleatorios e SSIDs ficticios.
//
// Uso: node scripts/make-demo-pcap.mjs [saida.pcap]

import { writeFileSync } from "node:fs";

const LINKTYPE_RADIOTAP = 127;

// Conjuntos de Information Elements por "modelo" de aparelho. O que importa e
// que modelos diferentes tenham combinacoes diferentes e que o mesmo aparelho
// mantenha a sua ao trocar de MAC.
const IE_PROFILE_A = [
  [1, Buffer.from([0x02, 0x04, 0x0b, 0x16])],
  [45, Buffer.concat([Buffer.from([0x2d, 0x40]), Buffer.alloc(24)])],
  [127, Buffer.from([0x00, 0x00, 0x08])],
  [221, Buffer.from([0x00, 0x50, 0xf2, 0x08])],
];
const IE_PROFILE_B = [
  [1, Buffer.from([0x82, 0x84, 0x8b, 0x96])],
  [45, Buffer.concat([Buffer.from([0xef, 0x09]), Buffer.alloc(24)])],
  [191, Buffer.from([0x32, 0x00, 0x80, 0x03])],
  [127, Buffer.from([0x04, 0x00, 0x0a])],
];

function macToBytes(mac) {
  return Buffer.from(mac.split(":").map((h) => parseInt(h, 16)));
}

/**
 * Cabecalho RadioTap minimo com Channel (bit 3) e dBm_AntSignal (bit 5), nessa
 * ordem de bits. Os campos ficam alinhados em relacao ao inicio do cabecalho,
 * exatamente como o leitor (parsing.ts) espera, entao canal e RSSI sao
 * decodificados.
 */
function radiotap(rssi, freq) {
  const buf = Buffer.alloc(13);
  buf.writeUInt8(0, 0); // versao
  buf.writeUInt8(0, 1); // pad
  buf.writeUInt16LE(13, 2); // tamanho total do cabecalho
  buf.writeUInt32LE((1 << 3) | (1 << 5), 4); // present: Channel + dBm_AntSignal
  buf.writeUInt16LE(freq, 8); // Channel: frequencia (MHz)
  buf.writeUInt16LE(0, 10); // Channel: flags
  buf.writeInt8(rssi, 12); // dBm_AntSignal (int8, com sinal)
  return buf;
}

/** Cabecalho de gerencia 802.11 de um probe request (24 bytes). */
function dot11ProbeReq(srcMac) {
  const buf = Buffer.alloc(24);
  buf.writeUInt8(0x40, 0); // Frame Control: type 0 (mgmt), subtype 4 (probe req)
  buf.writeUInt8(0x00, 1); // flags
  buf.writeUInt16LE(0, 2); // duration
  macToBytes("ff:ff:ff:ff:ff:ff").copy(buf, 4); // addr1 (destino: broadcast)
  macToBytes(srcMac).copy(buf, 10); // addr2 (origem)
  macToBytes("ff:ff:ff:ff:ff:ff").copy(buf, 16); // addr3 (BSSID: broadcast)
  buf.writeUInt16LE(0, 22); // sequence control
  return buf;
}

/** Serializa um Information Element [id (1), len (1), payload]. */
function ie(id, payload) {
  return Buffer.concat([Buffer.from([id, payload.length]), payload]);
}

/** Monta um quadro probe request completo (RadioTap + Dot11 + IEs). */
function probe(srcMac, ssid, ies, rssi = -55, freq = 2412) {
  const ssidBytes = ssid ? Buffer.from(ssid, "utf8") : Buffer.alloc(0);
  // SSID primeiro (comprimento zero = varredura generica), depois os IEs.
  const elements = [ie(0, ssidBytes), ...ies.map(([id, p]) => ie(id, p))];
  return Buffer.concat([radiotap(rssi, freq), dot11ProbeReq(srcMac), ...elements]);
}

/** Escreve um .pcap classico (cabecalho global 24 bytes + registros de 16). */
function writePcap(path, frames) {
  const global = Buffer.alloc(24);
  global.writeUInt32LE(0xa1b2c3d4, 0); // magic (little-endian)
  global.writeUInt16LE(2, 4); // versao major
  global.writeUInt16LE(4, 6); // versao minor
  global.writeUInt32LE(65535, 16); // snaplen
  global.writeUInt32LE(LINKTYPE_RADIOTAP, 20); // linktype
  const parts = [global];
  let ts = 1700000000; // timestamp fixo => arquivo byte-identico a cada geracao
  for (const frame of frames) {
    const rec = Buffer.alloc(16);
    rec.writeUInt32LE(ts, 0); // ts_sec
    rec.writeUInt32LE(0, 4); // ts_usec
    rec.writeUInt32LE(frame.length, 8); // incl_len
    rec.writeUInt32LE(frame.length, 12); // orig_len
    parts.push(rec, frame);
    ts += 1;
  }
  writeFileSync(path, Buffer.concat(parts));
}

function build(path) {
  const frames = [];

  // 1) Vitima com MAC fixo (OUI real da Apple) vazando a PNL inteira.
  const victim = "ac:bc:32:11:22:33";
  for (const ssid of [
    "HomeNet_4A2F",
    "Cafe do Joao",
    "AEROPORTO-FREE",
    "Trabalho-Corp",
    "HotelParis_502",
  ]) {
    frames.push(probe(victim, ssid, IE_PROFILE_A, -48));
  }

  // 2) Dois aparelhos que convivem: compartilham uma rede domestica rara.
  const roommate1 = "ac:bc:32:aa:bb:cc";
  const roommate2 = "d0:03:4b:dd:ee:ff";
  for (let i = 0; i < 3; i++) {
    frames.push(probe(roommate1, "Republica_303", IE_PROFILE_A, -60));
    frames.push(probe(roommate2, "Republica_303", IE_PROFILE_B, -62));
  }
  frames.push(probe(roommate2, "Academia Fit", IE_PROFILE_B, -70));

  // 3) Mesmo aparelho, dois MACs aleatorios, mesmo perfil de IEs: a assinatura
  //    reagrupa o que a randomizacao tentou separar.
  for (const mac of ["7a:11:22:33:44:55", "6e:aa:bb:cc:dd:ee"]) {
    for (let i = 0; i < 4; i++) {
      frames.push(probe(mac, null, IE_PROFILE_B, -65));
    }
    frames.push(probe(mac, "CasaDaVo", IE_PROFILE_B, -66));
  }

  // 4) Ruido: varreduras genericas de passantes.
  for (const mac of ["5e:01:02:03:04:05", "4a:0a:0b:0c:0d:0e"]) {
    frames.push(probe(mac, null, IE_PROFILE_A, -80));
  }

  writePcap(path, frames);
  console.log(`PCAP de demonstracao gerado em ${path} (${frames.length} quadros)`);
}

build(process.argv[2] ?? "demo_probes.pcap");
