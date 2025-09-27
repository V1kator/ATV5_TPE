import re
import csv
import tkinter as tk
from tkinter import filedialog, messagebox
from collections import defaultdict

# Regex para capturar dados do tcpdump:
# Exemplo: 00:00:00.000000 IP 192.168.0.16.57624 > 170.187.146.200.443:
REGEX = re.compile(r"(\d+):(\d+):(\d+\.\d+)\s+IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+):")

def analisar_trafego(arquivo):
    eventos_por_ip = defaultdict(list)  # {ip_origem: [(timestamp, porta_destino)]}

    with open(arquivo, "r") as f:
        for linha in f:
            match = REGEX.search(linha)
            if match:
                # Converter timestamp para segundos absolutos
                horas = int(match.group(1))
                minutos = int(match.group(2))
                segundos = float(match.group(3))
                timestamp = horas * 3600 + minutos * 60 + segundos

                ip_origem = match.group(4)
                porta_destino = match.group(7)

                eventos_por_ip[ip_origem].append((timestamp, porta_destino))

    resultado = []
    for ip, eventos in eventos_por_ip.items():
        total_eventos = len(eventos)
        portscan = "Não"

        # Detectar portscan
        eventos.sort(key=lambda x: x[0])  # ordenar por tempo
        for i in range(len(eventos)):
            t_inicial = eventos[i][0]
            portas = {eventos[i][1]}  # conjunto de portas distintas

            for j in range(i + 1, len(eventos)):
                if eventos[j][0] - t_inicial <= 60:  # dentro de 60 segundos
                    portas.add(eventos[j][1])
                else:
                    break

            if len(portas) > 10:
                portscan = "Sim"
                break

        resultado.append([ip, total_eventos, portscan])

    return resultado

def salvar_relatorio(dados, nome_arquivo="relatorio.csv"):
    with open(nome_arquivo, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "Total_Eventos", "Detectado_PortScan"])
        writer.writerows(dados)

def selecionar_arquivo():
    caminho = filedialog.askopenfilename(
        title="Selecione o arquivo de tráfego",
        filetypes=[("Arquivos de texto", "*.txt")]
    )
    if caminho:
        dados = analisar_trafego(caminho)
        salvar_relatorio(dados)
        messagebox.showinfo("Sucesso", f"Análise concluída!\nRelatório salvo em relatorio.csv")

# Interface gráfica
def main():
    root = tk.Tk()
    root.title("Analisador de Tráfego - Port Scan Detector")

    label = tk.Label(root, text="Selecione o arquivo trafego.txt para análise:", font=("Arial", 12))
    label.pack(pady=10)

    botao = tk.Button(root, text="Selecionar Arquivo", command=selecionar_arquivo, width=25)
    botao.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
