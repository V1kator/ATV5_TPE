README – Analisador de Tráfego e Detecção de Port Scan
📡 Captura de Tráfego
Para capturar o tráfego de rede por 60 segundos e salvar em um arquivo:
sudo tcpdump -i <interface> -nn -ttt ip > trafego.txt
•	Substitua <interface> por eth0, wlan0 ou equivalente.

•	O arquivo trafego.txt será usado pelo script Python.
—————
🐍 Execução do Script
1.	Salve o script em analisador.py.

2.	Execute:
python3 analisador.py
3.	Uma janela abrirá. Clique em Selecionar Arquivo e escolha o trafego.txt.

4.	O programa gera o arquivo relatorio.csv no mesmo diretório.
—————
📊 Interpretação do CSV
O relatório possui as seguintes colunas:
•	IP → Endereço IP de origem identificado no tráfego.

•	Total_Eventos → Quantidade de tentativas de conexão originadas por esse IP (cada linha analisada conta como um evento).

•	Detectado_PortScan →
–	Sim → se o IP tentou acessar mais de 10 portas diferentes em até 60 segundos.

–	Não → caso contrário.
—————
⚠️ Possíveis Limitações
•	Tráfego baixo: em redes com poucos pacotes, o script pode não identificar padrões suspeitos.

•	Falsos positivos: conexões legítimas (ex.: atualizações automáticas, serviços em nuvem) podem gerar acessos a muitas portas em pouco tempo.

•	Formato do arquivo: o script foi desenvolvido para processar saídas do tcpdump no formato padrão. Ajustes podem ser necessários em versões diferentes.

•	Escopo restrito: apenas IP de origem e portas são considerados; não há análise profunda de protocolos ou payloads.
