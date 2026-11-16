# 0002 - Porte para TypeScript e remoção do Python

**Data:** 2026-11-16
**Status:** aceito

## Contexto

A ferramenta nasceu em Python (ver [ADR 0001](0001-arquitetura-em-camadas-e-modos-de-privacidade.md)),
com a análise já isolada da captura em camadas testáveis. A decisão seguinte foi
reescrever tudo em **TypeScript rodando como CLI Node.js** e descontinuar o
Python, mantendo intactos a arquitetura em camadas e os modos de privacidade da
ADR 0001 — que continuam válidos.

Motivações:

- Um único ecossistema (Node.js) para distribuição e execução da CLI, sem exigir
  Python nem Scapy na máquina do avaliador.
- Tipagem estática e contratos de dados verificados em runtime (Zod) nas bordas
  (resumo, export JSON/CSV, opções da CLI).
- Eliminar a dependência do Scapy para interpretar quadros: o parser 802.11
  (RadioTap + Dot11 + Information Elements) passou a ser escrito à mão sobre
  `Buffer`, o que também destravou a leitura de `.pcapng`.

## Decisão

- Todo o código Python foi **removido** (`probesniffer/`, `wifi_probe_sniffer.py`,
  `tests/`, `tools/`, `requirements*.txt`, `setup_script.sh` e o guia de
  instalação Kali). O projeto TypeScript foi **promovido da subpasta `ts/` para a
  raiz** do repositório.
- A equivalência de comportamento foi preservada: mesmas camadas, mesmos modos de
  privacidade, e as chaves serializadas (JSON/CSV/`asDict`) permanecem em
  `snake_case` idênticas à versão Python; identificadores de domínio em
  `camelCase`.
- Testes migrados para **Vitest**. Além dos casos de análise, há um teste de
  equivalência do leitor `.pcapng` com o `.pcap` clássico.
- A captura ao vivo usa o addon nativo **`cap`** (libpcap/Npcap) como
  `optionalDependency`, importado dinamicamente — o fluxo offline e os testes
  rodam sem ele.
- O gerador do PCAP de demonstração foi portado de Scapy para TypeScript puro
  (`scripts/make-demo-pcap.mjs`); o `demo_probes.pcap` é versionado como fixture.

## Consequências

- Quem for rodar não precisa mais de Python/Scapy; precisa de Node.js. A captura
  ao vivo no Windows depende do Npcap (driver), que não se instala de forma
  automatizada — há `npm run setup:capture` para orientar/instalar por plataforma.
- A ADR 0001 segue como registro da arquitetura; esta ADR apenas troca a
  linguagem e a localização do código, sem revogá-la.
- Leitura de captura agora aceita `.pcap` clássico **e** `.pcapng`. O modo
  monitor e o salto de canal continuam dependendo de `iw`/`airmon-ng` (Linux).
