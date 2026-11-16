#!/usr/bin/env node
// Executado como postinstall: so informa se a captura ao vivo esta disponivel.
// NUNCA falha a instalacao (sempre sai com codigo 0) — o modo offline nao
// depende do addon nativo. Quem so vai ler .pcap/.pcapng ignora este aviso.

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

try {
  require("cap");
  console.log("[wifi-probescope] captura ao vivo disponivel (addon 'cap' OK).");
} catch {
  const hint =
    process.platform === "win32"
      ? "instale o Npcap + SDK + Build Tools e rode: npm run setup:capture (veja o README)"
      : "rode: npm run setup:capture";
  console.log(
    `[wifi-probescope] modo offline pronto. Para captura ao vivo (-i), ${hint}.`,
  );
}

process.exit(0);
