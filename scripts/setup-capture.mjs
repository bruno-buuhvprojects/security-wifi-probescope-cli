#!/usr/bin/env node
// Prepara a dependencia nativa de captura ao vivo: o addon "cap", binding do
// libpcap (Linux/macOS) ou Npcap (Windows).
//
// Linux: instala headers do libpcap + toolchain via setup-capture-linux.sh e
//        recompila o "cap".
// macOS: o libpcap ja vem no sistema; so recompila (precisa das Command Line
//        Tools do Xcode).
// Windows: o Npcap e um DRIVER; sua instalacao exige elevacao, aceite de EULA e
//        o Npcap SDK para compilar. Isso nao se automatiza em silencio: aqui so
//        detectamos e orientamos (e sugerimos o comando do Chocolatey, se houver).
//
// Uso: npm run setup:capture

import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const PKG_ROOT = join(HERE, "..");

/** Verdadeiro se o addon "cap" carrega (ja compilado e utilizavel). */
function capAvailable() {
  try {
    require("cap");
    return true;
  } catch {
    return false;
  }
}

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { stdio: "inherit", ...opts });
}

function has(cmd) {
  const probe = spawnSync(cmd, ["--version"], { stdio: "ignore" });
  return probe.status === 0;
}

/** Recompila o "cap" a partir do codigo nativo ja com as deps presentes. */
function rebuildCap() {
  console.log("\n> Recompilando o addon 'cap'...");
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const r = run(npm, ["rebuild", "cap"], { cwd: PKG_ROOT });
  if (r.status !== 0) {
    console.error(
      "\nA recompilacao do 'cap' falhou. Confira as mensagens do node-gyp acima.",
    );
    return false;
  }
  return true;
}

function finish() {
  if (capAvailable()) {
    console.log("\n[OK] Captura ao vivo disponivel: o addon 'cap' carregou.");
    process.exit(0);
  }
  console.error(
    "\n[!] O 'cap' ainda nao carrega. Reveja os passos acima; o modo offline (-r) continua funcionando.",
  );
  process.exit(1);
}

function setupLinux() {
  const sh = join(HERE, "setup-capture-linux.sh");
  const r = run("bash", [sh]);
  if (r.status !== 0) {
    console.error(
      "\nInstalacao das dependencias de sistema falhou. Veja as mensagens acima.",
    );
    process.exit(1);
  }
  rebuildCap();
  finish();
}

function setupMac() {
  console.log("== Setup de captura ao vivo (macOS) ==");
  console.log(
    "O libpcap ja acompanha o macOS. Sera preciso ter as Command Line Tools do Xcode\n" +
      "(instale com: xcode-select --install) para compilar o addon.",
  );
  rebuildCap();
  console.log(
    "\nDica: capturar em modo monitor no macOS pode exigir rodar com sudo.",
  );
  finish();
}

function guideWindows() {
  console.log("== Setup de captura ao vivo (Windows) ==\n");
  console.log(
    "A captura ao vivo no Windows depende do Npcap, que e um driver de rede. Por\n" +
      "ser driver, a instalacao NAO pode ser automatizada aqui (exige elevacao/UAC e\n" +
      "aceite da licenca). Compilar o addon 'cap' precisa, alem do driver, do SDK e\n" +
      "das Build Tools. Passos:\n",
  );
  console.log("  1. Npcap (runtime): https://npcap.com/#download");
  console.log("     - marque \"Install Npcap in WinPcap API-compatible Mode\".");
  console.log("  2. Npcap SDK (headers/libs): https://npcap.com/#download");
  console.log(
    "     - extraia e aponte a variavel de ambiente NPCAP_SDK para a pasta do SDK.",
  );
  console.log(
    "  3. Build Tools do Visual Studio (C++) + Python 3:\n" +
      "     winget install Microsoft.VisualStudio.2022.BuildTools --override \"--add Microsoft.VisualStudio.Workload.VCTools\"",
  );
  if (has("choco")) {
    console.log(
      "\n  Detectei o Chocolatey. Em um terminal como Administrador voce pode usar:\n" +
        "     choco install npcap -y",
    );
  }
  console.log("\n  Depois de instalar o acima, rode novamente: npm run setup:capture");

  if (capAvailable()) {
    rebuildCap();
    finish();
  } else {
    console.log(
      "\n[i] Enquanto o Npcap/SDK nao estiverem prontos, use o modo offline: node dist/cli.js -r captura.pcap",
    );
    process.exit(0); // nao e erro: orientacao entregue.
  }
}

function main() {
  if (capAvailable()) {
    console.log("[OK] O addon 'cap' ja esta disponivel; nada a fazer.");
    process.exit(0);
  }
  switch (process.platform) {
    case "linux":
      return setupLinux();
    case "darwin":
      return setupMac();
    case "win32":
      return guideWindows();
    default:
      console.log(
        `Plataforma '${process.platform}' nao coberta automaticamente. Instale os headers do\n` +
          "libpcap e um toolchain C/C++, depois rode: npm rebuild cap",
      );
      process.exit(0);
  }
}

main();
