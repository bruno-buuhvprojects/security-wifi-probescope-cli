// Testes das camadas de analise, independentes de hardware e de rede.
//
// Exercitam classificacao de MAC, fingerprint, anonimizacao, agregacao,
// inferencias de privacidade e simulacao de contramedidas com vetores
// sinteticos -- o que e possivel justamente porque a analise foi isolada da
// camada de captura. Porte fiel de tests/test_analysis.py.

import { describe, it, expect } from "vitest";

import { AnonymizationMode, MacAnonymizer } from "../src/anonymize.js";
import { buildFingerprint } from "../src/fingerprint.js";
import { classify, vendorResolvable } from "../src/macaddr.js";
import {
  CaptureStore,
  ProbeObservation,
  utcNow,
} from "../src/models.js";
import { assess } from "../src/inference.js";
import { scoreDevices, simulateCountermeasures } from "../src/defense.js";
import { buildSummary } from "../src/report.js";
import { SummarySchema } from "../src/schemas.js";

// --------------------------------------------------------------------------- //
// Classificacao de MAC
// --------------------------------------------------------------------------- //

describe("classificacao de MAC", () => {
  it("MAC fixo e reconhecido como global", () => {
    const result = classify("ac:bc:32:11:22:33");
    expect(result.isValid).toBe(true);
    expect(result.isRandomized).toBe(false);
    expect(vendorResolvable(result)).toBe(true);
    expect(result.oui).toBe("ac:bc:32");
  });

  it("MAC com bit local e randomizado sem OUI", () => {
    // Segundo nibble impar (bit 1 setado) => localmente administrado.
    const result = classify("7a:11:22:33:44:55");
    expect(result.isRandomized).toBe(true);
    expect(result.oui).toBeNull();
    expect(vendorResolvable(result)).toBe(false);
  });

  it.each(["", null, "nao-e-mac", "zz:zz:zz:zz:zz:zz"])(
    "MAC invalido: %s",
    (bad) => {
      expect(classify(bad).isValid).toBe(false);
    },
  );
});

// --------------------------------------------------------------------------- //
// Fingerprint
// --------------------------------------------------------------------------- //

describe("fingerprint", () => {
  it("mesmos IEs geram mesma assinatura", () => {
    const ies: Array<[number, Buffer]> = [
      [1, Buffer.from([0x02, 0x04])],
      [45, Buffer.from([0x2d, 0x40])],
      [221, Buffer.from([0x00, 0x50, 0xf2, 0x08])],
    ];
    expect(buildFingerprint(ies).digest).toBe(buildFingerprint(ies).digest);
  });

  it("IEs diferentes geram assinaturas diferentes", () => {
    const a = buildFingerprint([
      [1, Buffer.from([0x02, 0x04])],
      [45, Buffer.from([0x2d, 0x40])],
    ]);
    const b = buildFingerprint([
      [1, Buffer.from([0x82, 0x84])],
      [45, Buffer.from([0xef, 0x09])],
    ]);
    expect(a.digest).not.toBe(b.digest);
  });

  it("vendor specific entra apenas pelo OUI", () => {
    const fp = buildFingerprint([
      [221, Buffer.from([0x00, 0x50, 0xf2, 0x08, 0xde, 0xad, 0xbe, 0xef])],
    ]);
    expect(fp.vendorOuis).toEqual(["00:50:f2"]);
    expect(fp.hasWps).toBe(true);
  });
});

// --------------------------------------------------------------------------- //
// Anonimizacao
// --------------------------------------------------------------------------- //

describe("anonimizacao", () => {
  it("modo mascarado nao revela MAC", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.MASKED });
    const out = anon.represent("AC:BC:32:11:22:33");
    expect(out).not.toContain("ac:bc:32");
    expect(out.startsWith("id:")).toBe(true);
  });

  it("modo revelado mostra MAC normalizado", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.REVEAL });
    expect(anon.represent("AC:BC:32:11:22:33")).toBe("ac:bc:32:11:22:33");
    expect(anon.provenance()["contains_plaintext_identifiers"]).toBe(true);
  });

  it("pseudonimo estavel na sessao mas varia entre sessoes", () => {
    const a1 = new MacAnonymizer({ mode: AnonymizationMode.MASKED });
    const a2 = new MacAnonymizer({ mode: AnonymizationMode.MASKED });
    const mac = "ac:bc:32:11:22:33";
    expect(a1.represent(mac)).toBe(a1.represent(mac)); // estavel
    expect(a1.represent(mac)).not.toBe(a2.represent(mac)); // salt por sessao
  });

  it("salt fixo correlaciona sessoes", () => {
    const a1 = new MacAnonymizer({ mode: AnonymizationMode.MASKED, salt: "tcc" });
    const a2 = new MacAnonymizer({ mode: AnonymizationMode.MASKED, salt: "tcc" });
    expect(a1.represent("ac:bc:32:11:22:33")).toBe(
      a2.represent("ac:bc:32:11:22:33"),
    );
  });
});

// --------------------------------------------------------------------------- //
// Helpers de cenario
// --------------------------------------------------------------------------- //

function obs(
  mac: string,
  ssid: string | null,
  ies: Array<[number, Buffer]>,
  offset = 0,
  rssi: number | null = -55,
): ProbeObservation {
  return new ProbeObservation({
    macAddress: mac,
    ssid,
    rssi,
    channel: 1,
    sequenceNumber: 0,
    timestamp: new Date(utcNow().getTime() + offset * 1000),
    classification: classify(mac),
    fingerprint: buildFingerprint(ies),
  });
}

const PROFILE_A: Array<[number, Buffer]> = [
  [1, Buffer.from([0x02, 0x04])],
  [45, Buffer.from([0x2d, 0x40])],
];
const PROFILE_B: Array<[number, Buffer]> = [
  [1, Buffer.from([0x82, 0x84])],
  [191, Buffer.from([0x32, 0x00])],
];
const PROFILE_C: Array<[number, Buffer]> = [
  [1, Buffer.from([0x8c, 0x12])],
  [127, Buffer.from([0x04, 0x00, 0x0a])],
];

function scenario(): CaptureStore {
  const store = new CaptureStore();
  // Vitima MAC fixo com PNL rica.
  for (const s of ["HomeNet_4A2F", "Trabalho-Corp", "HotelParis_502"]) {
    store.add(obs("ac:bc:32:11:22:33", s, PROFILE_A));
  }
  // Dois conviventes compartilhando rede rara (perfis de radio distintos,
  // para que o vinculo venha do SSID e nao de colisao de fingerprint).
  store.add(obs("ac:bc:32:aa:bb:cc", "Republica_303", PROFILE_A));
  store.add(obs("d0:03:4b:dd:ee:ff", "Republica_303", PROFILE_C));
  // Mesmo aparelho, dois MACs aleatorios, mesmo fingerprint.
  for (const mac of ["7a:11:22:33:44:55", "6e:aa:bb:cc:dd:ee"]) {
    store.add(obs(mac, null, PROFILE_B));
  }
  return store;
}

// --------------------------------------------------------------------------- //
// Agregacao
// --------------------------------------------------------------------------- //

describe("agregacao", () => {
  it("store conta dispositivos e randomizados", () => {
    const store = scenario();
    expect(store.devices.size).toBe(5);
    expect(store.randomizedCount).toBe(2);
  });

  it("store deduplica SSIDs por dispositivo", () => {
    const store = new CaptureStore();
    store.add(obs("ac:bc:32:11:22:33", "Rede", PROFILE_A));
    store.add(obs("ac:bc:32:11:22:33", "Rede", PROFILE_A));
    expect(store.devices.get("ac:bc:32:11:22:33")!.ssids).toEqual(
      new Set(["Rede"]),
    );
    expect(store.devices.get("ac:bc:32:11:22:33")!.frameCount).toBe(2);
  });
});

// --------------------------------------------------------------------------- //
// Inferencias
// --------------------------------------------------------------------------- //

describe("inferencias", () => {
  it("infere vazamento de PNL", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.REVEAL });
    const assessment = assess(scenario(), anon);
    const victim = assessment.deviceInferences.find(
      (d) => d.deviceId === "ac:bc:32:11:22:33",
    )!;
    expect(victim.knownNetworks).toContain("HotelParis_502");
    expect(victim.leaksPreferredNetworks).toBe(true);
  });

  it("infere vinculo social por SSID raro", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.REVEAL });
    const assessment = assess(scenario(), anon);
    expect(
      assessment.socialLinks.some((link) =>
        link.sharedNetworks.includes("Republica_303"),
      ),
    ).toBe(true);
  });

  it("fingerprint derrota randomizacao", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.REVEAL });
    const assessment = assess(scenario(), anon);
    const groups = assessment.fingerprintDefeatsRandomization;
    expect(groups.length).toBeGreaterThan(0);
    expect(groups[0]["distinct_mac_count"]).toBe(2);
  });
});

// --------------------------------------------------------------------------- //
// Contramedidas
// --------------------------------------------------------------------------- //

describe("contramedidas", () => {
  it("suprimir PNL zera vazamento e vinculos", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.MASKED });
    const store = scenario();
    const rows = new Map<string, Record<string, unknown>>();
    for (const r of simulateCountermeasures(store, anon)) {
      rows.set(r["countermeasure"] as string, r["metrics"] as Record<string, unknown>);
    }

    const base = rows.get("sem_defesa")!;
    const onlyMac = rows.get("mac_randomization")!;
    const both = rows.get("mac_and_null")!;

    // So randomizar o MAC nao apaga a PNL nem os vinculos sociais.
    expect(onlyMac["devices_leaking_pnl"]).toBe(base["devices_leaking_pnl"]);
    expect(onlyMac["social_links"]).toBe(base["social_links"]);
    // Suprimir a PNL (junto da randomizacao) fecha o vetor dominante.
    expect(both["devices_leaking_pnl"]).toBe(0);
    expect(both["social_links"]).toBe(0);
  });

  it("ranking de exposicao prioriza MAC fixo com PNL", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.REVEAL });
    const scores = scoreDevices(scenario(), anon);
    expect(scores[0].deviceId).toBe("ac:bc:32:11:22:33");
    expect(["alta", "moderada"]).toContain(scores[0].level);
  });
});

// --------------------------------------------------------------------------- //
// Contrato Zod: o summary montado fecha com os asDict()
// --------------------------------------------------------------------------- //

describe("contrato Zod do summary", () => {
  it("buildSummary nao lanca e passa pelo SummarySchema", () => {
    const anon = new MacAnonymizer({ mode: AnonymizationMode.MASKED });
    const summary = buildSummary(scenario(), anon);
    // buildSummary ja valida internamente; reparse prova que o contrato fecha.
    expect(() => SummarySchema.parse(summary)).not.toThrow();
  });
});
