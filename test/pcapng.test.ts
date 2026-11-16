// Testes do leitor .pcapng, por equivalencia com o leitor .pcap classico.
//
// Em vez de forjar quadros 802.11 na mao (fragil), reaproveitamos os quadros
// crus do demo_probes.pcap: extraimos cada quadro do arquivo classico,
// reembrulhamos num .pcapng (SHB + IDB + um Enhanced Packet Block por quadro) e
// exigimos que a analise do .pcapng seja identica a do .pcap de origem. Cobrimos
// as duas ordens de bytes, little e big-endian.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync, writeFileSync, rmSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";

import { describe, it, expect } from "vitest";

import { readPcap } from "../src/capture.js";
import type { ProbeObservation } from "../src/models.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const DEMO_PCAP = join(HERE, "..", "demo_probes.pcap");
const LINKTYPE_RADIOTAP = 127;

/** Extrai os quadros crus de um .pcap classico little-endian (o do demo). */
function rawFramesFromClassicPcap(path: string): Buffer[] {
  const buf = readFileSync(path);
  const frames: Buffer[] = [];
  let offset = 24; // pula o cabecalho global
  while (offset + 16 <= buf.length) {
    const inclLen = buf.readUInt32LE(offset + 8);
    offset += 16;
    if (offset + inclLen > buf.length) {
      break;
    }
    frames.push(Buffer.from(buf.subarray(offset, offset + inclLen)));
    offset += inclLen;
  }
  return frames;
}

/** Arredonda para o proximo multiplo de 4 (alinhamento de bloco do pcapng). */
function pad4(n: number): number {
  return (n + 3) & ~3;
}

/** Monta um .pcapng (SHB + IDB radiotap + um EPB por quadro) na ordem pedida. */
function buildPcapng(frames: Buffer[], le: boolean): Buffer {
  const w32 = (b: Buffer, o: number, v: number): void => {
    if (le) {
      b.writeUInt32LE(v >>> 0, o);
    } else {
      b.writeUInt32BE(v >>> 0, o);
    }
  };
  const w16 = (b: Buffer, o: number, v: number): void => {
    if (le) {
      b.writeUInt16LE(v, o);
    } else {
      b.writeUInt16BE(v, o);
    }
  };

  // Section Header Block: type, total(28), BOM, versao 1.0, section length -1.
  const shb = Buffer.alloc(28);
  w32(shb, 0, 0x0a0d0d0a);
  w32(shb, 4, 28);
  w32(shb, 8, 0x1a2b3c4d); // byte-order magic, sempre escrito na ordem da secao
  w16(shb, 12, 1); // versao major
  w16(shb, 14, 0); // versao minor
  w32(shb, 16, 0xffffffff); // section length -1 (parte baixa)
  w32(shb, 20, 0xffffffff); // parte alta
  w32(shb, 24, 28);

  // Interface Description Block: linktype radiotap, snaplen 65535.
  const idb = Buffer.alloc(20);
  w32(idb, 0, 0x00000001);
  w32(idb, 4, 20);
  w16(idb, 8, LINKTYPE_RADIOTAP); // LinkType
  w16(idb, 10, 0); // reservado
  w32(idb, 12, 65535); // SnapLen
  w32(idb, 16, 20);

  const blocks: Buffer[] = [shb, idb];
  for (const frame of frames) {
    const padded = pad4(frame.length);
    const total = 32 + padded; // header(8) + 5 campos(20) + dados + trailer(4)
    const epb = Buffer.alloc(total);
    w32(epb, 0, 0x00000006); // Enhanced Packet Block
    w32(epb, 4, total);
    w32(epb, 8, 0); // Interface ID 0
    w32(epb, 12, 0); // timestamp high
    w32(epb, 16, 0); // timestamp low
    w32(epb, 20, frame.length); // Captured Len
    w32(epb, 24, frame.length); // Original Len
    frame.copy(epb, 28);
    w32(epb, 28 + padded, total); // trailer
    blocks.push(epb);
  }
  return Buffer.concat(blocks);
}

/** Resumo comparavel de uma captura: contagem e pares (mac, ssid) ordenados. */
function digest(observations: ProbeObservation[]): {
  count: number;
  pairs: string[];
} {
  const pairs = observations
    .map((o) => `${o.macAddress}|${o.ssid ?? ""}`)
    .sort();
  return { count: observations.length, pairs };
}

describe("leitor .pcapng", () => {
  const frames = rawFramesFromClassicPcap(DEMO_PCAP);
  const classic = digest([...readPcap(DEMO_PCAP)]);

  it("o demo tem quadros para comparar", () => {
    expect(frames.length).toBeGreaterThan(0);
    expect(classic.count).toBeGreaterThan(0);
  });

  for (const le of [true, false]) {
    const ordem = le ? "little-endian" : "big-endian";
    it(`analisa .pcapng ${ordem} identico ao .pcap de origem`, () => {
      const dir = mkdtempSync(join(tmpdir(), "wifi-probescope-"));
      const path = join(dir, `demo-${ordem}.pcapng`);
      try {
        writeFileSync(path, buildPcapng(frames, le));
        const ng = digest([...readPcap(path)]);
        expect(ng).toEqual(classic);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });
  }

  it("rejeita um .pcapng com byte-order magic invalido", () => {
    const dir = mkdtempSync(join(tmpdir(), "wifi-probescope-"));
    const path = join(dir, "ruim.pcapng");
    try {
      const bad = Buffer.alloc(28);
      bad.writeUInt32LE(0x0a0d0d0a, 0); // parece SHB...
      bad.writeUInt32LE(28, 4);
      bad.writeUInt32LE(0xdeadbeef, 8); // ...mas o BOM esta errado
      writeFileSync(path, bad);
      expect(() => [...readPcap(path)]).toThrow(/byte-order magic/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
