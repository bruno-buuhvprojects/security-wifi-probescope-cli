# wifi-probescope

CLI em **TypeScript/Node.js** para **analisar a exposição de privacidade em
probe requests 802.11**. Captura (ou lê de um `.pcap`/`.pcapng`) os quadros que
celulares e notebooks emitem ao procurar redes conhecidas e, a partir deles,
mostra o que um observador passivo consegue inferir — vazamento de PNL, vínculo
social por SSID raro, reidentificação por fingerprint apesar da randomização de
MAC — e mede o efeito de contramedidas.

## Propósito

Um dispositivo Wi-Fi, mesmo sem se conectar a nada, anuncia regularmente as
redes que já conheceu (a *Preferred Network List*, PNL). A ferramenta coleta
esses anúncios e evidencia, com números, três vetores de inferência:

- **Vazamento de PNL** — a lista de redes preferidas expõe casa, trabalho,
  hotéis e locais já visitados.
- **Vínculo social** — dois aparelhos que buscam a mesma rede rara
  provavelmente pertencem a pessoas que convivem.
- **Fingerprint de rádio** — a combinação de *Information Elements* identifica o
  modelo/driver e reagrupa um mesmo aparelho mesmo quando ele randomiza o MAC,
  mostrando na prática que **trocar o MAC, sozinho, não garante anonimato**.

Fecha o ciclo com um **ranking de exposição** por dispositivo e uma **simulação
de contramedidas** (randomização de MAC, supressão da PNL e a combinação das
duas), medindo quanto cada medida reduz do que foi inferido.

Por padrão o MAC **nunca** aparece em claro: cada endereço vira um pseudônimo
HMAC-SHA256 com salt aleatório por sessão. O modo `--reveal` existe apenas para
laboratório controlado e fica registrado na proveniência do arquivo exportado.

## Requisitos

- **Node.js 18+** (desenvolvido e testado com Node 26).
- Para **captura ao vivo** (opcional): o addon nativo `cap` (binding do
  libpcap/Npcap). Veja [Captura ao vivo — setup nativo](#captura-ao-vivo--setup-nativo).
  - O modo monitor e o salto de canal dependem de `iw`/`airmon-ng` (Linux).

O pacote `cap` é uma **dependência opcional**: se o build nativo falhar, a
instalação segue e todo o fluxo offline (leitura de `.pcap`/`.pcapng`, análise,
testes) funciona sem ele. O `cap` só é importado dinamicamente no caminho de
captura ao vivo.

### Captura ao vivo — setup nativo

Depois do `npm install`, um passo de `postinstall` informa se a captura ao vivo
está disponível. Para preparar o addon nativo, rode:

```bash
npm run setup:capture
```

O que o script faz, por plataforma:

- **Linux:** instala os headers do `libpcap` + toolchain (detecta
  apt/dnf/yum/pacman/zypper/apk, usando `sudo` quando necessário) e recompila o
  `cap`. Dica de execução sem root: `sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(command -v node))`.
- **macOS:** o `libpcap` já vem no sistema; o script apenas recompila o `cap`
  (requer as Command Line Tools do Xcode).
- **Windows:** o Npcap é um **driver**, então a instalação **não é
  automatizável** (exige elevação/UAC e aceite de licença). O script detecta o
  estado e orienta: instalar o [Npcap](https://npcap.com/#download) + o **Npcap
  SDK** (variável `NPCAP_SDK`) + as Build Tools do Visual Studio (C++); depois
  recompilar com `npm run setup:capture`.

## Instalação

```bash
npm install
npm run build
```

`npm run build` roda o `tsc` e gera `dist/`, incluindo o executável
`dist/cli.js`.

## Uso

Após o build, via `node dist/cli.js` (ou pelo bin `wifi-probescope`, se instalado
globalmente):

O repositório inclui um `demo_probes.pcap` pronto (gerável com `npm run demo:pcap`)
para uma demonstração reprodutível, sem adaptador nem root:

```bash
# Demonstração offline com o PCAP de exemplo versionado
node dist/cli.js -r demo_probes.pcap

# Modo offline (reprodutível): analisa um arquivo .pcap/.pcapng já gravado
node dist/cli.js -r captura.pcap

# Exporta o resultado em JSON (padrão) ou CSV
node dist/cli.js -r captura.pcap -o resultado.json
node dist/cli.js -r captura.pcap -o resultado.csv -f csv

# Captura ao vivo em uma interface, habilitando o modo monitor via airmon-ng
node dist/cli.js -i wlan0 --monitor

# Captura por tempo fixo, saltando por canais específicos
node dist/cli.js -i wlan0 --monitor -d 60 --channels 1,6,11,36

# Resolve fabricante por OUI após a captura
node dist/cli.js -r captura.pcap -V

# Modo revelado (MAC em claro) — APENAS em laboratório controlado e autorizado
node dist/cli.js -r captura.pcap --reveal

# Ajuda completa
node dist/cli.js --help
```

Principais opções:

| Flag | Descrição |
| --- | --- |
| `-i, --interface` | interface sem fio em modo monitor (captura ao vivo) |
| `-r, --read` | lê de um arquivo PCAP em vez de capturar (modo offline) |
| `-d, --duration` | duração da captura em segundos |
| `--channels` | lista de canais para o salto, ex.: `1,6,11,36` |
| `--no-hop` | desativa o salto de canal |
| `--monitor` | habilita/desabilita o modo monitor via `airmon-ng` |
| `--write-pcap` | grava os quadros capturados para reprodução |
| `--reveal` | exibe o MAC em claro (laboratório controlado) |
| `--anon-salt` | salt fixo para pseudônimos correlacionáveis entre sessões |
| `-V, --vendor-lookup` | resolve fabricante por OUI após a captura |
| `--oui-db` | base local de OUI (linhas `OUI,Fabricante`) |
| `-o, --output` | arquivo de resultados |
| `-f, --format` | formato do arquivo (`csv` ou `json`, padrão `json`) |
| `-q, --quiet` | suprime o log por quadro durante a captura |

## Validação de contratos com Zod

Os formatos **serializados** (JSON/CSV exportados, objeto `summary`, métricas das
contramedidas) são definidos como *schemas* [Zod](https://zod.dev/) em
`src/schemas.ts`, a fonte única de verdade dos contratos de saída. As chaves
serializadas ficam em `snake_case`, idênticas ao formato do pacote Python
original, para preservar a compatibilidade dos arquivos.

- `report.buildSummary` valida o relatório contra `SummarySchema` antes de
  retorná-lo (falha cedo se um `asDict()` divergir do contrato).
- A exportação valida o payload JSON inteiro (`JsonExportSchema`) e cada linha do
  CSV (`DeviceRowSchema`) antes de gravar.
- A CLI valida as opções já parseadas contra `CliOptionsSchema`.

## Execução dos testes

```bash
npm test
```

Os testes (Vitest) exercitam duas frentes, **sem hardware nem rede**:

- `test/analysis.test.ts` — classificação de MAC, fingerprint, anonimização,
  agregação, inferências de privacidade e simulação de contramedidas com vetores
  sintéticos, mais um teste que prova que o `summary` montado fecha com o
  contrato Zod.
- `test/pcapng.test.ts` — equivalência do leitor `.pcapng` com o `.pcap`
  clássico: reembrulha os quadros do demo em `.pcapng` (little e big-endian) e
  exige análise idêntica.

## Formatos de captura

A leitura detecta o formato pelo _magic_ dos primeiros bytes e suporta tanto o
**`.pcap` clássico** (micro e nanossegundo, little e big-endian) quanto o
**`.pcapng`** (PCAP Next Generation: blocos SHB/IDB/EPB/SPB, link-layer type por
interface). Só são interpretados os quadros de interfaces 802.11 (linktype 127 =
radiotap, 105 = 802.11 cru); quadros de interfaces não-802.11 na mesma captura
são ignorados sem abortar o arquivo.

## Limites conhecidos

- O **modo monitor** e o **salto de canal** dependem de `iw`/`airmon-ng` e, na
  prática, de Linux. Em Windows essas ferramentas não existem e os comandos
  correspondentes falham de forma controlada.
- A **captura ao vivo** depende do addon nativo `cap` e **não foi validada neste
  ambiente**; o fluxo exercitado e testado é o offline (leitura de `.pcap` e
  análise).
