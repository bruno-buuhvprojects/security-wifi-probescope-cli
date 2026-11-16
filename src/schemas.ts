// Contratos de dados (schemas Zod) e tipos inferidos.
//
// Este modulo e a FONTE DE VERDADE dos formatos SERIALIZADOS (chaves em
// snake_case, identicas ao Python) e das opcoes de CLI. Os demais modulos
// derivam seus tipos daqui via z.infer e validam seus objetos de saida contra
// estes schemas, de modo que qualquer divergencia de formato falhe cedo em vez
// de produzir um arquivo exportado invalido.
//
// Regra de dependencia: este arquivo NAO importa nenhum outro modulo do
// projeto (so o zod), para poder ser importado por qualquer um sem ciclo.

import { z } from "zod";

/** Metadados sobre o tratamento de identificadores aplicado ao conjunto. */
export const ProvenanceSchema = z.object({
  anonymization_mode: z.enum(["masked", "reveal"]),
  contains_plaintext_identifiers: z.boolean(),
  salt_scope: z.enum(["fixed", "per-session"]),
  pseudonym_algorithm: z.string(),
});
export type Provenance = z.infer<typeof ProvenanceSchema>;

/** Janela temporal da captura, com a procedencia embutida. */
export const SessionSchema = z.object({
  started_at: z.string(),
  finished_at: z.string(),
  duration_seconds: z.number(),
  provenance: ProvenanceSchema,
});
export type Session = z.infer<typeof SessionSchema>;

/** Contagens agregadas da sessao. */
export const TotalsSchema = z.object({
  frames_processed: z.number().int(),
  unique_devices: z.number().int(),
  randomized_mac_devices: z.number().int(),
  randomized_mac_ratio: z.number(),
  devices_with_vendor: z.number().int(),
  distinct_ssids: z.number().int(),
});
export type Totals = z.infer<typeof TotalsSchema>;

/** SSID mais procurado e quantas vezes foi requisitado. */
export const TopSsidSchema = z.object({
  ssid: z.string(),
  requests: z.number().int(),
});
export type TopSsid = z.infer<typeof TopSsidSchema>;

/** Inferencia de rede preferida (PNL) a partir dos probes direcionados. */
export const DeviceInferenceDtoSchema = z.object({
  device_id: z.string(),
  known_networks: z.array(z.string()),
  is_randomized: z.boolean(),
  distinctive_networks: z.array(z.string()),
});
export type DeviceInferenceDto = z.infer<typeof DeviceInferenceDtoSchema>;

/** Vinculo social entre dois dispositivos por redes conhecidas em comum. */
export const DeviceLinkDtoSchema = z.object({
  device_a: z.string(),
  device_b: z.string(),
  shared_networks: z.array(z.string()),
});
export type DeviceLinkDto = z.infer<typeof DeviceLinkDtoSchema>;

/** Grupo de fingerprint que reune varios MACs (randomizacao derrotada). */
export const FingerprintGroupSchema = z.object({
  fingerprint: z.string(),
  distinct_mac_count: z.number().int(),
  randomized_in_group: z.number().int(),
  device_ids: z.array(z.string()),
});
export type FingerprintGroup = z.infer<typeof FingerprintGroupSchema>;

/** Dispositivo recorrente (presenca prolongada ou com muitos quadros). */
export const RecurringDeviceSchema = z.object({
  device_id: z.string(),
  frame_count: z.number().int(),
  duration_seconds: z.number(),
  rssi_max: z.number().nullable(),
  is_randomized: z.boolean(),
});
export type RecurringDevice = z.infer<typeof RecurringDeviceSchema>;

/** Consolidado da avaliacao de privacidade. */
export const PrivacyAssessmentDtoSchema = z.object({
  devices_leaking_pnl: z.number().int(),
  device_inferences: z.array(DeviceInferenceDtoSchema),
  social_links: z.array(DeviceLinkDtoSchema),
  fingerprint_defeats_randomization: z.array(FingerprintGroupSchema),
  recurring_devices: z.array(RecurringDeviceSchema),
});
export type PrivacyAssessmentDto = z.infer<typeof PrivacyAssessmentDtoSchema>;

/** Metricas resultantes de uma contramedida simulada. */
export const CountermeasureMetricsSchema = z.object({
  devices_leaking_pnl: z.number().int(),
  social_links: z.number().int(),
  fingerprint_groups_defeating_randomization: z.number().int(),
  resolvable_vendors: z.number().int(),
});
export type CountermeasureMetrics = z.infer<typeof CountermeasureMetricsSchema>;

/** Linha da simulacao de contramedidas. */
export const CountermeasureRowSchema = z.object({
  countermeasure: z.string(),
  description: z.string(),
  metrics: CountermeasureMetricsSchema,
});
export type CountermeasureRow = z.infer<typeof CountermeasureRowSchema>;

/** Pontuacao de exposicao de um dispositivo. */
export const ExposureScoreDtoSchema = z.object({
  device_id: z.string(),
  score: z.number().int(),
  level: z.string(),
  reasons: z.array(z.string()),
});
export type ExposureScoreDto = z.infer<typeof ExposureScoreDtoSchema>;

/** Objeto "summary" completo do relatorio. */
export const SummarySchema = z.object({
  session: SessionSchema,
  totals: TotalsSchema,
  top_ssids: z.array(TopSsidSchema),
  privacy_assessment: PrivacyAssessmentDtoSchema,
  exposure_ranking: z.array(ExposureScoreDtoSchema),
  countermeasure_simulation: z.array(CountermeasureRowSchema),
});
export type Summary = z.infer<typeof SummarySchema>;

/** Linha de dispositivo exportada (CSV/JSON). */
export const DeviceRowSchema = z.object({
  device_id: z.string(),
  first_seen: z.string(),
  last_seen: z.string(),
  frame_count: z.number().int(),
  is_randomized: z.boolean(),
  oui: z.string(),
  vendor: z.string(),
  ssids: z.string(),
  fingerprints: z.string(),
  channels: z.string(),
  rssi_max: z.union([z.number(), z.literal("")]),
  rssi_mean: z.union([z.number(), z.literal("")]),
});
export type DeviceRow = z.infer<typeof DeviceRowSchema>;

/** Payload completo do export em JSON. */
export const JsonExportSchema = z.object({
  provenance: ProvenanceSchema,
  generated_at: z.string(),
  summary: SummarySchema.optional(),
  devices: z.array(DeviceRowSchema),
});
export type JsonExport = z.infer<typeof JsonExportSchema>;

/** Opcoes da CLI ja normalizadas. */
export const CliOptionsSchema = z.object({
  interface: z.string().optional(),
  read: z.string().optional(),
  durationSeconds: z.number().int().optional(),
  channels: z.array(z.number().int()).optional(),
  noHop: z.boolean().default(false),
  monitor: z.boolean().default(false),
  writePcap: z.string().optional(),
  reveal: z.boolean().default(false),
  anonSalt: z.string().optional(),
  vendorLookup: z.boolean().default(false),
  ouiDb: z.string().optional(),
  output: z.string().optional(),
  format: z.enum(["csv", "json"]).default("json"),
  quiet: z.boolean().default(false),
});
export type CliOptions = z.infer<typeof CliOptionsSchema>;
