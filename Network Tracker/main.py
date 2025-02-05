from scapy.all import sniff, conf
from collections import defaultdict
import time
import threading
from flask import Flask, render_template_string, jsonify
import datetime

# Configurar Scapy para usar L3RawSocket
conf.L3socket = conf.L3socket

class NetworkMonitor:
    def __init__(self):
        self.packet_counts = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.bytes_per_second = []
        self.start_time = time.time()
        self.lock = threading.Lock()

    def packet_callback(self, packet):
        with self.lock:
            # Contar paquetes por IP
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
                self.packet_counts[src_ip] += 1
                self.packet_counts[dst_ip] += 1

                # Identificar protocolo
                proto = packet["IP"].proto
                if proto == 6:  # TCP
                    self.protocol_counts["TCP"] += 1
                elif proto == 17:  # UDP
                    self.protocol_counts["UDP"] += 1
                elif proto == 1:  # ICMP
                    self.protocol_counts["ICMP"] += 1

                # Calcular bytes por segundo
                current_time = time.time()
                packet_size = len(packet)
                self.bytes_per_second.append((current_time, packet_size))

                # Mantener solo los últimos 60 segundos de datos
                cutoff_time = current_time - 60
                self.bytes_per_second = [(t, s) for t, s in self.bytes_per_second if t > cutoff_time]

    def get_statistics(self):
        with self.lock:
            current_time = time.time()
            
            # Calcular bytes por segundo para los últimos 60 segundos
            bytes_last_minute = sum(size for t, size in self.bytes_per_second)
            elapsed_time = max(1, current_time - self.start_time)
            bytes_per_second = bytes_last_minute / min(60, elapsed_time)

            return {
                "top_ips": dict(sorted(self.packet_counts.items(), 
                                     key=lambda x: x[1], 
                                     reverse=True)[:10]),
                "protocol_distribution": dict(self.protocol_counts),
                "bytes_per_second": round(bytes_per_second, 2),
                "total_packets": sum(self.packet_counts.values()) // 2,  # Dividir por 2 ya que contamos tanto src como dst
                "uptime": round(current_time - self.start_time, 2)
            }

# Inicializar Flask y el monitor
app = Flask(__name__)
monitor = NetworkMonitor()

# HTML template para la interfaz web (mismo que antes)
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Monitor de Red</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.7.0/chart.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { 
            border: 1px solid #ddd; 
            padding: 15px; 
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <h1>Monitor de Red en Tiempo Real</h1>
    <div class="container">
        <div class="card">
            <h2>Estadísticas Generales</h2>
            <p>Paquetes Totales: <span id="total-packets">0</span></p>
            <p>Bytes por Segundo: <span id="bytes-per-second">0</span> B/s</p>
            <p>Tiempo Activo: <span id="uptime">0</span> segundos</p>
        </div>
        <div class="card">
            <h2>Distribución de Protocolos</h2>
            <canvas id="protocolChart"></canvas>
        </div>
        <div class="card">
            <h2>Top 10 IPs más Activas</h2>
            <div id="top-ips"></div>
        </div>
    </div>

    <script>
        let protocolChart;

        function updateCharts(data) {
            // Actualizar estadísticas generales
            document.getElementById('total-packets').textContent = data.total_packets;
            document.getElementById('bytes-per-second').textContent = data.bytes_per_second;
            document.getElementById('uptime').textContent = data.uptime;

            // Actualizar top IPs
            const ipList = Object.entries(data.top_ips)
                .map(([ip, count]) => `<p>${ip}: ${count} paquetes</p>`)
                .join('');
            document.getElementById('top-ips').innerHTML = ipList;

            // Actualizar gráfico de protocolos
            const protocols = data.protocol_distribution;
            if (!protocolChart) {
                const ctx = document.getElementById('protocolChart').getContext('2d');
                protocolChart = new Chart(ctx, {
                    type: 'pie',
                    data: {
                        labels: Object.keys(protocols),
                        datasets: [{
                            data: Object.values(protocols),
                            backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56']
                        }]
                    }
                });
            } else {
                protocolChart.data.datasets[0].data = Object.values(protocols);
                protocolChart.update();
            }
        }

        // Actualizar datos cada segundo
        setInterval(() => {
            fetch('/stats')
                .then(response => response.json())
                .then(data => updateCharts(data));
        }, 1000);
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/stats')
def stats():
    return jsonify(monitor.get_statistics())

def start_sniffing():
    # Usar filter para capturar solo paquetes IP
    sniff(prn=monitor.packet_callback, store=0, filter="ip")

if __name__ == '__main__':
    # Iniciar la captura de paquetes en un hilo separado
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    
    # Iniciar el servidor web
    app.run(host='0.0.0.0', port=5000, debug=False)