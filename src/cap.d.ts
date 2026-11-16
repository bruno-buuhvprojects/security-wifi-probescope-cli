// O addon nativo "cap" (libpcap/Npcap) nao publica tipos. E uma
// optionalDependency importada dinamicamente so na captura ao vivo; esta
// declaracao ambiente o trata como `any`, de modo que o `tsc` compile tanto com
// o addon instalado quanto sem ele (caminho offline/analise/testes).
declare module "cap";
