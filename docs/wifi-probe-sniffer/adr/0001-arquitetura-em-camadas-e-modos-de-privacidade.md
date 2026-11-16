# 0001 - Arquitetura em camadas e modos de privacidade

**Data:** 2026-11-15
**Status:** aceito

## Contexto

A versão 1.0 era um único script (`wifi_probe_sniffer.py`) com toda a lógica
acoplada ao Scapy e ao hardware, estado em variáveis globais e nenhum teste.
Isso trazia problemas concretos:

- A análise não podia ser exercitada sem um adaptador em modo monitor e root,
  o que também impedia uma demonstração acadêmica reprodutível.
- O estado global impedia processar duas capturas no mesmo processo.
- Havia incoerência de privacidade: o console mascarava o MAC, mas o CSV/JSON
  gravavam o endereço em claro.
- Bugs de captura passavam despercebidos por falta de testes: a interface era
  renomeada pelo `airmon-ng` e o código seguia lendo o nome antigo; o SSID só
  era lido do primeiro Information Element; o vendor lookup fazia I/O de rede
  dentro do callback de pacote, descartando quadros.

O objetivo da reescrita é um trabalho de conclusão que **demonstra o risco de
privacidade dos probe requests e mede contramedidas**. Isso exige evidência
reproduzível e um tratamento de dado pessoal defensável perante a banca.

## Decisão

1. **Separação em três camadas** dentro do pacote `probesniffer/`:
   captura (`capture.py`, `parsing.py`) isola tudo que depende de Scapy/rádio;
   análise (`macaddr`, `fingerprint`, `models`, `inference`, `defense`) opera
   sobre `ProbeObservation` e não conhece hardware; apresentação (`report`,
   `cli`) cuida de relatório e exportação. Só `parsing.py` e `capture.py`
   importam o Scapy, o que torna a análise testável offline.

2. **Estado em objetos, não em globais**: `CaptureStore` guarda o estado da
   sessão, permitindo testes isolados e múltiplas capturas por processo.

3. **Dois modos de identificação, escolhidos explicitamente** (`anonymize.py`):
   *mascarado* (padrão) pseudonimiza o MAC com HMAC-SHA256 e salt por sessão;
   *revelado* (`--reveal`) expõe o MAC em claro, destinado a laboratório
   controlado — por exemplo, provar os dados reais para a banca. Um único ponto
   (`MacAnonymizer.represent`) decide entre as duas formas, garantindo que
   console e arquivo nunca divirjam. O modo fica registrado na proveniência do
   arquivo exportado.

4. **Modo offline por PCAP** (`-r`/`--write-pcap`): leitura e escrita de `.pcap`
   para que a demonstração rode sem hardware e os testes sejam reprodutíveis.

5. **Fingerprint por Information Elements e contramedidas simuladas** como
   núcleo de pesquisa: `inference.py` evidencia o que se deduz das pessoas e
   `defense.py` quantifica o efeito de cada defesa sobre os mesmos dados.

## Consequências

- A análise é coberta por testes (`tests/test_analysis.py`) que rodam sem
  adaptador nem root; a demonstração de banca é reprodutível via PCAP sintético
  (`tools/make_demo_pcap.py`).
- O comando histórico `python wifi_probe_sniffer.py` é preservado: o arquivo
  virou um entrypoint fino que delega para `probesniffer.cli`.
- O formato de saída mudou (novas colunas: fingerprint, canal, contagem de
  quadros, randomização) e o padrão passou a ser JSON; scripts que consumiam o
  CSV 1.0 precisam de ajuste.
- O modo revelado grava dado pessoal em claro por desenho; a proveniência no
  arquivo e o aviso em log mitigam, mas a responsabilidade de uso autorizado
  permanece com o operador.
- O reagrupamento por fingerprint é uma capacidade de rastreamento real; é
  mantido por ser o ponto central da demonstração, sempre sobre identificadores
  mascarados por padrão.
