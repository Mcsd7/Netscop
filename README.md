# 📡 NetScope

**Radar de conexões de rede para Android + Termux, sem root.**

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)
![Plataforma](https://img.shields.io/badge/Plataforma-Android%20%2B%20Termux-3DDC84?logo=android&logoColor=white)
![Root](https://img.shields.io/badge/Root-n%C3%A3o%20necess%C3%A1rio-brightgreen)
![Licença](https://img.shields.io/badge/Licen%C3%A7a-MIT-blue)

O NetScope mostra, direto no terminal, com quem o seu Android está se comunicando: IPs, domínios, país, operadora, serviço e app. Ele também sinaliza destinos em blocklists de malware, tráfego sem criptografia e portas suspeitas, tudo com uma interface colorida estilo hacking.

Criado pelo canal **Offtec** (segurança da informação).

<!-- Coloque aqui um print do terminal:
![NetScope](docs/print.png)
-->

---

## ✨ Funcionalidades

| # | Opção | O que faz |
|---|-------|-----------|
| 1 | **Monitor ao vivo** | Conexões em tempo real, estatísticas, velocidade de rede e gráfico de atividade |
| 2 | **Conexões** | TCP/UDP com serviço, país e app (UID) |
| 3 | **Domínios** | Destinos agrupados por domínio (DNS reverso) |
| 4 | **Geolocalização & ASN** | País, cidade e operadora de cada IP de destino |
| 5 | **Blocklist** | Cruza as conexões com listas de IPs/domínios maliciosos e permite checar manualmente |
| 6 | **Análise de risco** | Tráfego sem criptografia, portas suspeitas, portas expostas e excesso de conexões |
| 7 | **Rede & Wi-Fi** | IP local, canal, RSSI com barra de sinal e tráfego total |
| 8 | **Exportar** | Salva um relatório em JSON e CSV |
| 9 | **Atualizar listas** | Baixa as blocklists mais recentes |
| i | **Limitações** | Explica o que não dá para fazer sem root |

---

## 🚀 Instalação

Abra o Termux e rode:

```bash
pkg update -y
pkg install python -y
pip install rich
curl -O https://raw.githubusercontent.com/Mcsd7/netscope/main/netscope.py
python netscope.py
```

### Opcional: informações de Wi-Fi

Para ver SSID, canal e sinal na opção **7**:

```bash
pkg install termux-api -y
```

Instale também o app **Termux:API** (F-Droid) e conceda a permissão de localização.

### Opcional: exportar para a pasta Downloads

```bash
termux-setup-storage
```

Sem isso, os relatórios são salvos na pasta do próprio Termux.

---

## 🕹️ Como usar

```bash
python netscope.py            # abre o menu
python netscope.py --no-geo   # desativa a geolocalização online
```

Digite o número da opção e pressione ENTER. No monitor ao vivo, use **Ctrl+C** para voltar ao menu.

**Legenda das tabelas**

- `⚠` destino presente em blocklist
- `!` tráfego em texto claro (HTTP, FTP, Telnet etc.)
- `PA` país do destino
- `APP` UID do app (ou nome do pacote, quando o aparelho permite)

---

## 📁 Arquivos criados

| Caminho | Conteúdo |
|---------|----------|
| `~/.netscope/` | Blocklists baixadas |
| `~/.netscope/custom_blocklist.txt` | Sua lista própria (um IP ou domínio por linha) |
| `~/storage/downloads/netscope_exports/` | Relatórios JSON/CSV (ou `~/netscope_exports/` sem acesso ao armazenamento) |

---

## ⚠️ Limitações (sem root)

O NetScope **não substitui** uma ferramenta de captura de pacotes. Sem root, o Android não permite:

- ❌ Captura de pacotes / arquivos PCAP (exige VPN local ou root)
- ❌ Inspeção profunda de protocolo e descriptografia de TLS (o protocolo é estimado pela porta)
- ❌ Firewall e bloqueio de conexões (exige VPN local)
- ❌ Bytes por conexão (só o tráfego total da interface)

Pontos de atenção:

- O **domínio** vem do DNS reverso (PTR), não do SNI do TLS. CDNs podem aparecer sem nome ou com nome genérico.
- O **app** aparece como UID. O nome do pacote só aparece se o comando `pm` funcionar no seu aparelho.
- A análise de risco usa listas e portas conhecidas. Ela aponta indícios, **não prova** que há malware ou espionagem.

💡 Combine com o **PCAPdroid**: ele captura o tráfego, o NetScope ajuda a analisar e exportar.

---

## 🛠️ Solução de problemas

**"Sem acesso a /proc/net" ou "Acesso bloqueado"**
O Android 10+ restringe essa leitura para apps recentes. Use o Termux do F-Droid ou do GitHub, que costuma funcionar. Algumas versões do Android bloqueiam mesmo assim.

**SSID aparece como `<unknown ssid>`**
Ative a localização do aparelho e conceda a permissão ao Termux:API.

**Geolocalização sem resposta**
Verifique a internet. Se você usa `--no-geo`, essa função fica desativada de propósito.

**Blocklist vazia**
Rode a opção **9** para baixar as listas.

---

## 🔒 Privacidade

- Tudo é lido localmente do seu aparelho.
- A geolocalização consulta o serviço **ip-api.com**, então os **IPs de destino** são enviados a ele. Use `--no-geo` para evitar isso.
- As blocklists são baixadas de fontes públicas (Feodo Tracker e URLhaus, do abuse.ch).
- Nenhum dado é enviado para o autor da ferramenta.

---

## ⚖️ Uso ético

Esta ferramenta é para **monitorar o seu próprio dispositivo** e para fins educacionais e defensivos. Não use para monitorar aparelhos ou redes de terceiros sem autorização. O autor não se responsabiliza pelo mau uso.

---

## 🤝 Contribuindo

Sugestões e pull requests são bem-vindos. Ideias para o futuro:

- Histórico de conexões entre execuções
- Alertas quando um novo destino suspeito aparecer
- Mais fontes de blocklist
- Temas de cores

---

## 📺 Offtec

Conteúdo sobre segurança da informação, ferramentas e scripts feitos no Android/Termux.
Canal no YouTube: **Offtec**

---

## 📄 Licença

Distribuído sob a licença **MIT**. Veja o arquivo `LICENSE`.
