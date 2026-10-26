# Relatório de Laboratório: Defense in Depth (Firewall + Forward Proxy + Reverse Proxy)

Este repositório documenta a implementação da 2ª Etapa do Cyber Range, evoluindo a segurança de perímetro básica para uma arquitetura de múltiplas camadas (*Defense in Depth*). Foram adicionados controles de aplicação (L7) utilizando Squid como Forward Proxy para a LAN e NGINX como Reverse Proxy para a DMZ.

---

## 1. Topologia, Zonas de Segurança e Fluxos

A rede foi segmentada em quatro zonas isoladas, com o tráfego rigidamente controlado pelo Firewall (`fw`).

* **Zonas:** WAN (Externa), LAN (Interna), DMZ (Serviços Públicos) e MGMT (Gerência).
* **Fluxo de Saída (Egress):** `LAN` → `Squid (10.0.1.20:3128)` → `Firewall (eth1 para eth0)` → `Internet`.
* **Fluxo de Entrada (Ingress):** `Internet` → `Firewall (eth0 para eth2)` → `NGINX (10.0.2.10:80)` → `Web (10.0.2.20:80)`.
* **Fluxo Interno:** `MGMT (adm)` → `Firewall (eth3 para eth2)` → `NGINX (10.0.2.10:80)` → `Web (10.0.2.20:80)`.

![Visao_Topologia](Visao_Topologia.jpg)

### Tabela de Mapeamento dos Nós e Zonas

| Zona de Segurança | Nó | IP / Máscara | Interface | Gateway Padrão | Função |
| --- | --- | --- | --- | --- | --- |
| **WAN** | `r0` | `198.51.100.2/30` | `eth0` / `eth1` | Bridge (Hospedeiro) | Roteador de Borda com NAT |
| **WAN** | `fw` | `198.51.100.1/30` | `eth0` | `198.51.100.2` | Interface Externa do Firewall |
| **LAN** | `fw` | `10.0.1.1/24` | `eth1` | — | Interface Interna do Firewall |
| **LAN** | `pc1` | `10.0.1.10/24` | `eth0` | `10.0.1.1` | Estação de Trabalho |
| **LAN** | `pc2` | `10.0.1.11/24` | `eth0` | `10.0.1.1` | Estação Comprometida (Bloqueio L2/L7) |
| **LAN** | `proxy` | `10.0.1.20/24` | `eth0` | `10.0.1.1` | Forward Proxy e Cache (Squid) |
| **DMZ** | `fw` | `10.0.2.1/24` | `eth2` | — | Interface DMZ do Firewall |
| **DMZ** | `rp` | `10.0.2.10/24` | `eth0` | `10.0.2.1` | Reverse Proxy (NGINX) |
| **DMZ** | `web` | `10.0.2.20/24` | `eth0` | `10.0.2.1` | Servidor Web Privado (HTTP) |
| **DMZ** | `dns` | `10.0.2.11/24` | `eth0` | `10.0.2.1` | Servidor DNS Interno |
| **MGMT** | `adm` | `10.0.3.1/24` | `eth3` | — | Interface MGMT do Firewall |
| **MGMT** | `adm` | `10.0.3.10/24` | `eth0` | `10.0.3.1` | Estação de Gerenciamento do Admin |

---

## 2. Política de Segurança de Perímetro (`fw.startup`)

O Firewall de Perímetro atua sob o princípio **Default Deny** (Bloqueio Padrão), aceitando conexões de entrada (`INPUT`) e encaminhamento (`FORWARD`) apenas mediante regras explícitas.

### Matriz de Regras do `iptables`
```bash
#Politica Padrao: BLOQUEAR POR PADRAO (Default Deny)
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP

# Permitir retorno de conexoes ja ESTABELECIDAS ou RELACIONADAS
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# -------------------------------------------------------------
# REGRAS INTERNAS (LAN / DMZ)
# -------------------------------------------------------------
# Permite consultas DNS da LAN para o servidor DNS da DMZ (10.0.2.11)
iptables -A FORWARD -i eth1 -o eth2 -s 10.0.1.0/24 -d 10.0.2.11 -p udp --dport 53 -j ACCEPT

# -------------------------------------------------------------
# FLUXOS PERMITIDOS DE SAÍDA (Egress) - Permite atualização do APT nos nós
# -------------------------------------------------------------
# Regras para o nó 'proxy' (10.0.1.20) acessar repositórios e DNS
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.20 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.20 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 10.0.1.20 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# Regras para o nó 'rp' (10.0.2.10) acessar repositórios e DNS
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.2.10 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.2.10 -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A FORWARD -i eth2 -o eth0 -s 10.0.2.10 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# -------------------------------------------------------------
# FLUXOS PERMITIDOS DE ENTRADA (Ingress)
# -------------------------------------------------------------
# Permite tráfego HTTP da Internet EXCLUSIVAMENTE para o NGINX (rp - 10.0.2.10)
iptables -A FORWARD -i eth0 -o eth2 -d 10.0.2.10 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Permite tráfego HTTP do nó adm para o NGINX (rp - 10.0.2.10)
iptables -A FORWARD -i eth3 -o eth2 -d 10.0.2.10 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
```

---

## 3. Forward Proxy e Cache (Squid) — Controle de Saída

Instalado no nó `proxy` (`10.0.1.20`), o Squid inspeciona e controla as requisições HTTP originadas na LAN antes de transitarem para o firewall e a Internet.

### Regras de Acesso e Cache (`/etc/squid/squid.conf`)
```text
http_port 3128

# Definição de Redes e Recursos (ACLs)
acl rede_lan src 10.0.1.0/24
acl pc2_comprometido src 10.0.1.11
acl dominios_proibidos dstdomain .proibido.com .redesocial.com

# Regras de Controle de Acesso (Ordem de avaliação é crítica)
http_access deny pc2_comprometido
http_access deny dominios_proibidos
http_access allow rede_lan
http_access deny all

# Configuração de Cache em Memória e Disco
cache_mem 64 MB
maximum_object_size_in_memory 512 KB
cache_dir ufs /var/spool/squid 100 16 256
maximum_object_size 4 MB
```



---

### Evidências Práticas
#### A. Navegação Intermediada (LAN → Squid → Internet)
O acesso direto à Internet foi bloqueado no Firewall. A navegação só ocorre exportando as variáveis de proxy na estação (`pc1`):

```bash
root@pc1:/# export http_proxy="http://10.0.1.20:3128"
root@pc1:/# export https_proxy="http://10.0.1.20:3128"
root@pc1:/# curl -v -x http://10.0.1.20:3128   -o /dev/null   http://neverssl.com/
 % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0*   Trying 10.0.1.20:3128...
* Connected to 10.0.1.20 (10.0.1.20) port 3128 (#0)
> GET http://neverssl.com/ HTTP/1.1
> Host: neverssl.com
> User-Agent: curl/7.88.1
> Accept: */*
> Proxy-Connection: Keep-Alive
>
  0     0    0     0    0     0      0      0 --:--:--  0:00:03 --:--:--     0< HTTP/1.1 200 OK
< Date: Sun, 25 Oct 2026 21:32:08 GMT
< Server: Apache/2.4.68 ()
< Last-Modified: Wed, 29 Jun 2022 00:23:33 GMT
< ETag: "f79-5e28b29d38e93"
< Accept-Ranges: bytes
< Content-Length: 3961
< Vary: Accept-Encoding
< Content-Type: text/html; charset=UTF-8
< X-Cache: MISS from proxy
< X-Cache-Lookup: MISS from proxy:3128
< Via: 1.1 proxy (squid/5.7)
< Connection: keep-alive
<
{ [1448 bytes data]
100  3961  100  3961    0     0   1155      0  0:00:03  0:00:03 --:--:--  1155
* Connection #0 to host 10.0.1.20 left intact
```

Tentativa de acesso direto (burlando o proxy) bloqueada pelo Firewall:

```bash
root@pc1:~# unset http_proxy
root@pc1:/# curl -i --connect-timeout 3 http://157.173.205.94
curl: (28) Failed to connect to 157.173.205.94 port 80 after 3001 ms: Timeout was reached

```

#### B. Bloqueio de Domínio via ACL no Squid (L7)
Domínios definidos na ACL `dominios_proibidos` são rejeitados pelo proxy, retornando uma página de erro ao invés de um descarte silencioso:

```bash
root@pc1:/# curl -I http://proibido.com
HTTP/1.1 403 Forbidden
Server: squid/5.7
Mime-Version: 1.0
Date: Sun, 25 Oct 2026 21:34:46 GMT
Content-Type: text/html;charset=utf-8
```

#### C. Funcionamento do Cache e Logs
As requisições interceptadas são registradas no arquivo de acesso do Squid, permitindo auditar o uso da rede e identificar a origem exata do recurso (Direto, Cache ou Negado):

```text
root@proxy:/# tail -f /var/log/squid/access.log
1792963927.592   3427 10.0.1.10 TCP_MISS/200 4339 GET http://neverssl.com/ - HIER_DIRECT/34.223.124.45 text/html
1792963960.889      0 10.0.1.10 TCP_MEM_HIT/200 4346 GET http://neverssl.com/ - HIER_NONE/- text/html
1792964086.618      0 10.0.1.10 TCP_DENIED/403 359 HEAD http://proibido.com/ - HIER_NONE/- text/html
```

* **Acesso Inicial (Recurso buscado na origem):**
```text
1792963927.592   3427 10.0.1.10 TCP_MISS/200 4339 GET http://neverssl.com/ - HIER_DIRECT/34.223.124.45 text/html

```


* **Acesso Subsequente (Servido pelo Cache da Memória RAM):**
```text
1792963960.889      0 10.0.1.10 TCP_MEM_HIT/200 4346 GET http://neverssl.com/ - HIER_NONE/- text/html

```

* **Investigação Firewall L3 vs. Proxy L7:** O bloqueio L3 no Firewall utiliza endereços IP. Se o IP hospedar múltiplos sites (como em CDNs), bloqueamos serviços legítimos (*overblocking*), e a regra falha se o IP mudar. O Squid atua em L7, inspecionando o cabeçalho `Host` ou a negociação SNI no HTTPS, bloqueando o domínio exato de forma cirúrgica, independente do IP de destino.

---

## 4. Reverse Proxy (NGINX) — Proteção de Entrada

Configurado no nó `rp` (`10.0.2.10`), o NGINX recebe o tráfego público e atua como a única porta de entrada para a aplicação situada no servidor `web` (`10.0.2.20`).

### Configuração Geral (`/etc/nginx/nginx.conf`)

Define a zona global de limitação de requisições por endereço IP:

```nginx
http {
    # Rate Limiting: Zona de 10MB limitando a 2 requisições por segundo por IP
    limit_req_zone $binary_remote_addr zone=one:10m rate=2r/s;
    
    include /etc/nginx/mime.types;
    include /etc/nginx/sites-enabled/*;
}

```


### Configuração do Virtual Host (`/etc/nginx/sites-available/default`)

```nginx
server {
    listen 80 default_server;
    server_name _;

    # CONTROLE L7 #1: Rate Limiting
    limit_req zone=one burst=5 nodelay;

    # Encaminhamento Padrão para o servidor Web da DMZ
    location / {
        proxy_pass http://10.0.2.20:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    # CONTROLE L7 #2: Proteção e Restrição de Acesso à Rota /admin
    location /admin {
        allow 10.0.3.0/24;  # Permite acesso exclusivo da rede MGMT
        deny all;           # Bloqueia qualquer outra origem (WAN/LAN)
        proxy_pass http://10.0.2.20:80;
    }

    # CONTROLE L7 #3: Restrição de Métodos HTTP
    location /public {
        proxy_pass http://10.0.2.20:80;
        limit_except GET POST {
            deny all; # Bloqueia métodos perigosos como DELETE, PUT, OPTIONS
        }
    }

    # CONTROLE L7 #4: Limitação do tamanho de requisições
    client_max_body_size 1m;

    # CONTROLE L7 #5: Headers Globais de Segurança
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;
    }

```


### Evidências Práticas do Reverse Proxy

#### A. Acesso Permitido (Internet → NGINX → Web)
Requisições externas permitidas são intermediadas e servidas com sucesso:

```bash
root@r0:/# curl -i http://10.0.2.10/
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sun, 25 Oct 2026 21:38:24 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1000
Connection: keep-alive
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```

**B. Bloqueio do Acesso Direto (Internet → Web)**
Tentativa de ignorar o NGINX conectando direto ao servidor web:

```bash
root@r0:/# curl -i --connect-timeout 3 http://10.0.2.20/
curl: (28) Failed to connect to 10.0.2.20 port 80 after 3000 ms: Timeout was reached
```
A política *Default Deny* no Firewall impede o desvio do Reverse Proxy

**C. Controles Adicionais Implementados no NGINX**

1. **Bloqueio de Rota Sensível (`/admin`):** Oculta áreas administrativas de acesso externo.
```bash
root@r0:/# curl -i http://10.0.2.10/admin
HTTP/1.1 403 Forbidden
Server: nginx/1.22.1
Date: Sun, 25 Oct 2026 21:40:32 GMT
Content-Type: application/octet-stream
Content-Length: 47
Connection: keep-alive
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

Acesso Negado pelo Reverse Proxy de Perimetro.
```

2. **Acesso à Rota `/admin` a partir da Estação de Gerenciamento (`adm` - `10.0.3.10`):**
```bash
root@adm:/# curl -i http://10.0.2.10/admin
HTTP/1.1 404 File not found
Server: nginx/1.22.1
Date: Mon, 26 Oct 2026 00:15:35 GMT
Content-Type: text/html;charset=utf-8
Content-Length: 335
Connection: keep-alive
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

<!DOCTYPE HTML>
```

3. **Restrição de Métodos HTTP (`limit_except`):** O endpoint `/public` aceita apenas `GET` e `POST`.
```bash
root@r0:/# curl -i -X DELETE http://10.0.2.10/public
HTTP/1.1 403 Forbidden
Server: nginx/1.22.1
Date: Sun, 25 Oct 2026 21:41:15 GMT
Content-Type: text/html
Content-Length: 153
Connection: keep-alive
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.22.1</center>
</body>
</html>
```


4. **Rate limiting:** Limita a frequência de requisições por IP.
```bash
root@r0:/# for i in $(seq 1 20); do     curl -s -o /dev/null -w "%{http_code}\n"     http://10.0.2.10/; done
200
200
200
200
200
200
503
503
503
503
503
503
503
503
503
503
503
503
503
503
```


5. **Limitação do tamanho das requisições:** Impede que o cliente envie um corpo HTTP maior que o limite definido.
```bash
root@r0:/# dd if=/dev/zero of=/tmp/teste.bin bs=1024 count=2048 #Esse comando cria um arquivo de teste de aproximadamente 2 MiB.
root@r0:/# curl -i -X POST   --data-binary @/tmp/teste.bin   http://10.0.2.10/public
HTTP/1.1 413 Request Entity Too Large
Server: nginx/1.22.1
Date: Sun, 25 Oct 2026 21:47:35 GMT
Content-Type: text/html
Content-Length: 183
Connection: close
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer

<html>
<head><title>413 Request Entity Too Large</title></head>
<body>
<center><h1>413 Request Entity Too Large</h1></center>
<hr><center>nginx/1.22.1</center>
</body>
</html
```


6. **Headers de segurança:** Adiciona cabeçalhos HTTP que ajudam os navegadores a aplicar proteções contra determinados tipos de ataque.
```bash
root@r0:/# curl -s -D - -o /dev/null http://10.0.2.10/
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Sun, 25 Oct 2026 21:48:18 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 1000
Connection: keep-alive
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
```


---

## 5. Análise de Defense in Depth (DiD) e Componentes

### Cenário 1: Falha de Configuração no Firewall (Liberação Inadvertida de Tráfego HTTP)

* **Hipótese:** O administrador adiciona acidentalmente a regra `FORWARD -i eth0 -o eth2 -p tcp --dport 80 -j ACCEPT`, permitindo conexões de qualquer IP da WAN para qualquer servidor da DMZ.
* **Atuação da Segunda Camada (NGINX):** Mesmo que um atacante consiga alcançar a porta 80 do `rp`, o NGINX continua aplicando as políticas de segurança de aplicação:
* Tentativas de acessar a rota `/admin` continuarão sendo bloqueadas com HTTP `403` para origens fora do bloco MGMT (`10.0.3.0/24`).
* Requisições maliciosas utilizando verbos HTTP como `DELETE` ou `PUT` serão barradas com HTTP `405`.
* Ataques de força bruta serão contidos pelo *Rate Limiting* (`2r/s`), impedindo a exaustão de recursos da aplicação no servidor `web`.

### Cenário 2: Comprometimento do Servidor `web` via Vulnerabilidade de Aplicação (RCE)

* **Hipótese:** Um atacante explora uma falha no código da aplicação e obtém acesso *shell* de execução remota no container `web` (`10.0.2.20`).
* **Barreiras de Contenção Restantes:**
1. **Isolamento de Egress no Firewall:** A regra de firewall padrão `FORWARD DROP` não possui liberações para tráfego originado no IP `10.0.2.20`. O atacante não consegue abrir uma *Reverse Shell* para a Internet nem escanear a LAN.
2. **Assimetria Funcional dos Proxies:** O NGINX (`10.0.2.10`) opera exclusivamente como um proxy de aplicação de camada 7 e recusa tráfego de roteamento de pacotes IP. O atacante na DMZ não possui caminho de rede L3 para alcançar as estações da LAN.


### **Firewall vs. Forward Proxy vs. Reverse Proxy:**
| Dimensão de Análise | Firewall (`fw`) | Forward Proxy (`proxy`) | Reverse Proxy (`rp`) |
| --- | --- | --- | --- |
| **Camada Predominante** | L3 (Rede) / L4 (Transporte). | L7 (Aplicação). | L7 (Aplicação). |
| **Posicionamento** | Fronteira entre sub-redes. | Interno à LAN (Lado do Cliente). | DMZ (Frente dos Servidores). |
| **Direcionamento do Fluxo** | Trânsito bidirecional de pacotes. | **Saída (Egress):** Cliente $\rightarrow$ WAN. | **Entrada (Ingress):** WAN $\rightarrow$ Servidor. |
| **Informação Inspecionada** | IPs, Portas, Protocolos, Conntrack. | URLs, Domínios, HTTP Headers, Cache. | Rotas URI, Métodos, SSL, Body Size. |
| **Efeito de Falha do Nó** | Bloqueia a conectividade de rede. | Interrompe a saída da LAN para a Web. | Oculta a aplicação e deixa o serviço offline. |

### Por que manter os três componentes em vez de apenas o Proxy?

O **Firewall** atua no nível do kernel do sistema operacional com alta performance, blindando a infraestrutura contra ataques volumétricos, varreduras de portas (TCP/UDP) e conexões maliciosas em níveis de transporte e rede. Os **Proxies** operam no espaço de usuário, processando a semântica fina de protocolos da camada de aplicação (HTTP/HTTPS).

Se o Firewall fosse removido, a infraestrutura ficaria completamente vulnerável a explorações de rede não-HTTP (como ataques ICMP, exploração de vulnerabilidades no stack IP e conexões diretas aos serviços do sistema operacional). A combinação dos três componentes cria o equilíbrio arquitetural do *Defense in Depth*.

---

## 6. Registro de Aprendizagem (SRL) — "Como Aprendemos"

### Tabela de Mapeamento de Dúvidas e Resoluções
| Dúvida / Problema | Fonte Consultada | O que aprendemos | Como validamos no laboratório |
| --- | --- | --- | --- |
| **Falha de inicialização do Squid no Kathará** (conflito de PID e permissões ao iniciar o container). | Documentação Oficial do Squid & Manpages do Debian. | O pacote Squid tenta iniciar automaticamente na instalação via `apt`, gerando locks no arquivo `/run/squid.pid`. É necessário limpar o PID e forçar a recriação do diretório de cache (`squid -z`). | Adicionado `pkill -9 squid` e `squid -z` no script `proxy.startup` antes da chamada `service squid start`. |
| **Tráfego LAN → Proxy caindo nas regras do Firewall.** | Análise de Cabeçalho Ethernet com `tcpdump`. | Hosts na mesma sub-rede IP (`10.0.1.0/24`) comunicam-se via Camada 2 (Switching/ARP) diretamente. O tráfego `PC1 -> Proxy` não passa pela interface de roteamento do Firewall (`FORWARD`). | Removida a regra redundante `FORWARD -i eth1 -o eth1` do firewall. Validado que `pc1` alcança `10.0.1.20:3128` via switch L2, comprovando a ineficácia da regra L3 em tráfego L2. |
| **Sintaxe para restrição de métodos HTTP no NGINX.** | Documentação do Módulo `ngx_http_core_module` do NGINX. | O bloco `limit_except` permite definir quais métodos HTTP **não** sofrerão a restrição declarada dentro dele. | Executado `curl -X DELETE` recebendo erro `405 Not Allowed`, enquanto `curl -X GET` retornou `200 OK`. |


### Reflexão Final

**Qual foi a principal coisa que tivemos que aprender por conta própria nesta Task?**
A forte dependência entre as camadas de rede. A arquitetura exigiu compreender exatamente o ciclo de vida do pacote: sem DNS liberado e roteado corretamente no Firewall, a instalação dos pacotes L7 falhava. Entender que Proxies quebram o modelo de confiança fim-a-fim da Internet foi o maior salto conceitual.

**Qual fonte foi mais útil e por quê?**
A documentação cruzada (man pages) das ferramentas combinada com ferramentas de IA Generativa. A IA foi crucial para dissecar o log do NGINX e identificar erros conceituais na nossa arquitetura de L2 vs L3, explicando o "porquê" de forma cirúrgica.

**Alguma solução encontrada na Internet ou sugerida por GenAI estava errada, incompleta ou não funcionou? Como descobrimos?**
Sim. Diversos tutoriais recomendavam criar regras de `FORWARD` no `iptables` entre o `pc1` e o `proxy`. Descobrimos que a orientação estava incorreta ao executar o `tcpdump` no nó `fw` e constatar que o tráfego da LAN para o Proxy sequer tocava na interface do firewall, provando que a comunicação era restrita à Camada 2. 

**O que faríamos de maneira diferente?**
Teríamos estruturado as configurações dos arquivos squid.conf e nginx.conf utilizando arquivos de inclusão separados para as ACLs, facilitando a manutenção e a auditoria das regras de segurança de aplicação.