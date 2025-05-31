import sys
import threading
import time
import socket
import ipaddress
import csv
import os
import json
import logging
import pandas as pd
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QInputDialog
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from ping3 import ping
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QLineEdit, QLabel, QMessageBox, 
    QFileDialog, QTabWidget, QStatusBar, QSpinBox
)
from PyQt5.QtCore import QTimer, Qt, pyqtSignal, QObject
from PyQt5.QtGui import QColor

logging.basicConfig(
    filename='ping_monitor.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SignalEmitter(QObject):
    add_host_signal = pyqtSignal(str)
    scan_completed_signal = pyqtSignal(int)
    scan_error_signal = pyqtSignal(str)
    update_status_signal = pyqtSignal(str)
    alert_signal = pyqtSignal(str)
    update_table_signal = pyqtSignal(int, list)

class PingMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor de Ping Mejorado")
        self.setWindowIcon(QIcon("icono.ico"))
        self.resize(1200, 700)
        self.hosts = []
        self.results = {}
        self.alert_thresholds = {}
        self.load_settings()

        self.signals = SignalEmitter()
        self.signals.add_host_signal.connect(self._add_host_gui)
        self.signals.scan_completed_signal.connect(self._scan_done)
        self.signals.scan_error_signal.connect(self._scan_error)
        self.signals.update_status_signal.connect(self.update_status)
        self.signals.alert_signal.connect(self.show_alert)
        self.signals.update_table_signal.connect(self._update_table_row)

        self.init_ui()
        self.timer = QTimer()
        self.timer.timeout.connect(self.perform_ping)
        self.timer.setInterval(self.timer_interval)

    def init_ui(self):
        layout = QVBoxLayout()

        # Configuración de intervalo
        config_layout = QHBoxLayout()
        config_layout.addWidget(QLabel("Intervalo de ping (ms):"))
        
        self.interval_spin = QSpinBox()
        self.interval_spin.setRange(1000, 60000)
        self.interval_spin.setValue(self.timer_interval)
        self.interval_spin.valueChanged.connect(self.update_ping_interval)
        config_layout.addWidget(self.interval_spin)
        
        layout.addLayout(config_layout)

        # Entrada de hosts
        input_layout = QHBoxLayout()
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Ingrese IP o dominio")
        input_layout.addWidget(self.host_input)

        add_button = QPushButton("Agregar Host")
        add_button.clicked.connect(self.add_host)
        add_button.setToolTip("Agrega un host individual para monitorear")
        input_layout.addWidget(add_button)

        import_button = QPushButton("Importar Hosts")
        import_button.clicked.connect(self.import_hosts)
        import_button.setToolTip("Importa una lista de hosts desde archivo")
        input_layout.addWidget(import_button)

        detect_button = QPushButton("Detectar Hosts Activos")
        detect_button.clicked.connect(self.detect_active_hosts)
        detect_button.setToolTip("Escanea la red local en busca de hosts activos")
        input_layout.addWidget(detect_button)

        clear_button = QPushButton("Limpiar Lista")
        clear_button.clicked.connect(self.clear_hosts)
        clear_button.setToolTip("Elimina todos los hosts monitoreados")
        input_layout.addWidget(clear_button)

        layout.addLayout(input_layout)

        # Tabs principal
        self.tabs = QTabWidget()

        # Tabla de hosts
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Host", "Estado", "Latencia Promedio (ms)", 
            "Paquetes Perdidos", "Último Ping (ms)", "Umbral Alerta (ms)"
        ])
        self.table.cellClicked.connect(self.plot_selected_host)
        self.table.cellDoubleClicked.connect(self.set_alert_threshold)
        self.tabs.addTab(self.table, "Tabla de Hosts")

        # Gráfico de latencia
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.tabs.addTab(self.canvas, "Gráfico de Latencia")

        layout.addWidget(self.tabs)

        # Botones de control
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("Iniciar Monitoreo")
        self.start_button.clicked.connect(self.start_monitoring)
        self.start_button.setToolTip("Inicia el monitoreo periódico")
        button_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Detener Monitoreo")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        self.stop_button.setToolTip("Detiene el monitoreo")
        button_layout.addWidget(self.stop_button)

        export_button = QPushButton("Exportar a Excel")
        export_button.clicked.connect(self.export_to_excel)
        export_button.setToolTip("Exporta estadísticas a archivo Excel")
        button_layout.addWidget(export_button)

        export_pdf_button = QPushButton("Exportar Gráfico")
        export_pdf_button.clicked.connect(self.export_graph_to_pdf)
        export_pdf_button.setToolTip("Exporta el gráfico a PDF")
        button_layout.addWidget(export_pdf_button)

        layout.addLayout(button_layout)

        # Barra de estado
        self.status_bar = QStatusBar()
        layout.addWidget(self.status_bar)
        self.update_status("Listo")

        self.setLayout(layout)

    def update_ping_interval(self):
        self.timer_interval = self.interval_spin.value()
        self.timer.setInterval(self.timer_interval)
        self.save_settings()

    def load_settings(self):
        try:
            with open('config.json') as f:
                settings = json.load(f)
                self.timer_interval = settings.get('interval', 5000)
                self.alert_thresholds = settings.get('alerts', {})
                if 'hosts' in settings:
                    for host in settings['hosts']:
                        if host not in self.hosts:
                            self._add_host_gui(host)
                logging.info("Configuración cargada correctamente")
        except (FileNotFoundError, json.JSONDecodeError):
            self.timer_interval = 5000
            self.alert_thresholds = {}
            self.save_settings()
            logging.warning("Configuración no encontrada, creando nueva")

    def save_settings(self):
        with open('config.json', 'w') as f:
            json.dump({
                'interval': self.timer_interval,
                'alerts': self.alert_thresholds,
                'hosts': self.hosts
            }, f)
        logging.info("Configuración guardada")

    def add_host(self):
        host = self.host_input.text().strip()
        if host and host not in self.hosts:
            self._add_host_gui(host)
            self.save_settings()
        self.host_input.clear()

    def import_hosts(self):
        path, _ = QFileDialog.getOpenFileName(
            self, 
            "Seleccionar archivo", 
            "", 
            "Archivos de texto (*.txt);;Archivos CSV (*.csv);;Archivos Excel (*.xlsx)"
        )
        
        if path:
            try:
                if path.endswith(".txt"):
                    with open(path, 'r') as file:
                        for line in file:
                            host = line.strip()
                            if host and host not in self.hosts:
                                self._add_host_gui(host)
                elif path.endswith(".csv"):
                    with open(path, 'r') as file:
                        reader = csv.reader(file)
                        for row in reader:
                            if row and row[0] not in self.hosts:
                                self._add_host_gui(row[0])
                elif path.endswith(".xlsx"):
                    df = pd.read_excel(path)
                    for host in df.iloc[:, 0]:
                        if pd.notna(host) and str(host) not in self.hosts:
                            self._add_host_gui(str(host))
                
                self.save_settings()
                self.update_status(f"Hosts importados desde {os.path.basename(path)}")
                logging.info(f"Hosts importados desde {path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo importar: {str(e)}")
                logging.error(f"Error al importar hosts: {str(e)}")

    def clear_hosts(self):
        reply = QMessageBox.question(
            self, 
            "Confirmar", 
            "¿Está seguro que desea limpiar todos los hosts?",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.hosts.clear()
            self.results.clear()
            self.alert_thresholds.clear()
            self.table.setRowCount(0)
            self.figure.clear()
            self.canvas.draw()
            self.save_settings()
            self.update_status("Lista de hosts limpiada")
            logging.info("Lista de hosts limpiada")

    def _add_host_gui(self, host):
        self.hosts.append(host)
        self.results[host] = {"pings": [], "lost": 0}
        
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        self.table.setItem(row, 0, QTableWidgetItem(host))
        for col in range(1, 6):
            self.table.setItem(row, col, QTableWidgetItem("-"))
            
        # Establecer umbral de alerta si existe
        if host in self.alert_thresholds:
            self.table.setItem(row, 5, QTableWidgetItem(str(self.alert_thresholds[host])))

    def start_monitoring(self):
        if not self.hosts:
            QMessageBox.warning(self, "Advertencia", "No hay hosts para monitorear")
            return

        if not os.path.exists("historial_latencias.csv"):
            with open("historial_latencias.csv", "w", newline="") as file:
                writer = csv.writer(file)
                writer.writerow(["Timestamp", "Host", "Estado", "Latencia (ms)"])

        self.timer.start()
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.update_status(f"Monitoreo iniciado - Intervalo: {self.timer_interval}ms")
        logging.info("Monitoreo iniciado")

    def stop_monitoring(self):
        self.timer.stop()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.update_status("Monitoreo detenido")
        logging.info("Monitoreo detenido")

    def perform_ping(self):
        self.update_status("Realizando ping a hosts...")
        threading.Thread(target=self._ping_all_threaded, daemon=True).start()

    def _ping_all_threaded(self):
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(self._ping_host, host): host for host in self.hosts}
            
            for future in as_completed(futures):
                host = futures[future]
                try:
                    result = future.result()
                    self.process_ping_result(host, result)
                except Exception as e:
                    logging.error(f"Error procesando ping a {host}: {str(e)}")
        
        self.signals.update_status_signal.emit("Monitoreo activo")

    def _ping_host(self, host):
        try:
            return ping(host, timeout=2)
        except Exception as e:
            logging.error(f"Error al hacer ping a {host}: {str(e)}")
            return None

    def process_ping_result(self, host, delay):
        if host not in self.results:
            self.results[host] = {"pings": [], "lost": 0}
            
        row = self.hosts.index(host)
        
        if delay is None:
            self.results[host]["lost"] += 1
            state = "Offline"
            last = "-"
            avg = self._calc_avg(host)
        else:
            ms = round(delay * 1000, 2)
            self.results[host]["pings"].append(ms)
            state = "Online"
            last = str(ms)
            avg = self._calc_avg(host)
            
            # Verificar alertas
            if host in self.alert_thresholds and ms > self.alert_thresholds[host]:
                self.signals.alert_signal.emit(
                    f"¡Alerta! {host} superó el umbral: {ms}ms > {self.alert_thresholds[host]}ms"
                )

        self.log_ping_result(host, delay)
        
        # Actualizar UI
        items = [
            host,
            state,
            avg,
            str(self.results[host]["lost"]),
            last,
            str(self.alert_thresholds.get(host, "-"))
        ]
        
        self.signals.update_table_signal.emit(row, items)

    def _update_table_row(self, row, items):
        for col, value in enumerate(items):
            if self.table.item(row, col) is None:
                self.table.setItem(row, col, QTableWidgetItem(value))
            else:
                self.table.item(row, col).setText(value)
                
        # Resaltar fila según estado
        color = QColor(255, 200, 200) if items[1] == "Offline" else QColor(200, 255, 200)
        for col in range(self.table.columnCount()):
            self.table.item(row, col).setBackground(color)

    def log_ping_result(self, host, latency):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        estado = "Online" if latency is not None else "Offline"
        ms = round(latency * 1000, 2) if latency else "-"
        
        try:
            with open("historial_latencias.csv", "a", newline="") as file:
                writer = csv.writer(file)
                writer.writerow([timestamp, host, estado, ms])
        except Exception as e:
            logging.error(f"Error al guardar registro: {str(e)}")

    def export_to_excel(self):
        if not self.hosts:
            QMessageBox.warning(self, "Advertencia", "No hay datos para exportar.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self, 
            "Guardar archivo", 
            "estadísticas_ping.xlsx", 
            "Archivos Excel (*.xlsx)"
        )
        
        if path:
            try:
                data = []
                for host in self.hosts:
                    avg = self._calc_avg(host)
                    lost = self.results.get(host, {}).get("lost", 0)
                    pings = self.results.get(host, {}).get("pings", [])
                    last = pings[-1] if pings else "-"
                    threshold = self.alert_thresholds.get(host, "-")
                    data.append([host, avg, lost, last, threshold])

                df = pd.DataFrame(data, columns=[
                    "Host", "Latencia Promedio", "Paquetes Perdidos", 
                    "Último Ping", "Umbral Alerta"
                ])
                df.to_excel(path, index=False)
                
                self.update_status(f"Estadísticas exportadas a {path}")
                logging.info(f"Datos exportados a {path}")
                QMessageBox.information(self, "Éxito", f"Datos exportados a {path}")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo exportar: {str(e)}")
                logging.error(f"Error al exportar a Excel: {str(e)}")

    def export_graph_to_pdf(self):
        if not self.hosts or not self.figure.axes:
            QMessageBox.warning(self, "Advertencia", "No hay gráfico para exportar.")
            return

        path, _ = QFileDialog.getSaveFileName(
            self,
            "Guardar gráfico como PDF",
            "grafico_latencia.pdf",
            "Archivos PDF (*.pdf)"
        )

        if path:
            try:
                self.figure.savefig(path)
                self.update_status(f"Gráfico exportado a {path}")
                logging.info(f"Gráfico exportado a {path}")
                QMessageBox.information(self, "Éxito", f"Gráfico exportado a {path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo exportar el gráfico: {str(e)}")
                logging.error(f"Error al exportar gráfico: {str(e)}")

    def detect_active_hosts(self):
        reply = QMessageBox.question(
            self, 
            "Confirmar", 
            "¿Escanear la red local? Esto puede tomar varios minutos.",
            QMessageBox.Yes | QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.update_status("Escaneando red local...")
            threading.Thread(target=self._scan_network_threaded, daemon=True).start()

    def _scan_network_threaded(self):
        try:
            local_ip = self.get_local_ip()
            if not local_ip:
                self.signals.scan_error_signal.emit("No se pudo obtener la IP local.")
                return

            net = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            found = 0
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(ping, str(ip), timeout=0.5): ip 
                    for ip in net.hosts() 
                    if str(ip) != local_ip
                }
                
                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        if future.result():
                            if str(ip) not in self.hosts:
                                self.signals.add_host_signal.emit(str(ip))
                                found += 1
                    except:
                        continue

            self.signals.scan_completed_signal.emit(found)
            self.signals.update_status_signal.emit("Escaneo completado")
            logging.info(f"Escaneo completado - {found} hosts encontrados")
            
        except Exception as e:
            self.signals.scan_error_signal.emit(f"Error en escaneo: {str(e)}")
            logging.error(f"Error en escaneo de red: {str(e)}")

    def set_alert_threshold(self, row, col):
        if col == 5:  # Columna de umbral de alerta
            host = self.table.item(row, 0).text()
            current = self.alert_thresholds.get(host, "")
            
            threshold, ok = QInputDialog.getInt(
                self, 
                f"Umbral de alerta para {host}",
                "Ingrese el umbral de latencia (ms):",
                int(current) if current.isdigit() else 100, 
                0, 10000, 100
            )
            
            if ok:
                self.alert_thresholds[host] = threshold
                self.table.setItem(row, 5, QTableWidgetItem(str(threshold)))
                self.save_settings()
                self.update_status(f"Umbral para {host} establecido en {threshold}ms")
                logging.info(f"Umbral para {host} establecido en {threshold}ms")

    def update_status(self, message):
        self.status_bar.showMessage(message)

    def show_alert(self, message):
        QMessageBox.warning(self, "Alerta de Red", message)
        logging.warning(f"ALERTA: {message}")

    def plot_selected_host(self, row, column):
        host = self.table.item(row, 0).text()
        if host not in self.results:
            return
            
        pings = self.results[host]["pings"][-20:]  # Últimos 20 pings

        self.figure.clear()
        ax = self.figure.add_subplot(111)
        
        ax.plot(pings, marker='o', linestyle='-', color='blue')
        ax.set_title(f"Latencia de {host} (últimos {len(pings)} pings)")
        ax.set_xlabel("Ping Nº")
        ax.set_ylabel("Tiempo (ms)")
        
        # Dibujar línea de umbral de alerta si existe
        if host in self.alert_thresholds:
            ax.axhline(
                y=self.alert_thresholds[host], 
                color='r', 
                linestyle='--', 
                label=f"Umbral: {self.alert_thresholds[host]}ms"
            )
            ax.legend()
            
        ax.grid(True)
        self.canvas.draw()
        self.update_status(f"Gráfico actualizado para {host}")

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            logging.error(f"Error al obtener IP local: {str(e)}")
            return None

    def _calc_avg(self, host):
        if host not in self.results:
            return "-"
            
        pings = self.results[host]["pings"]
        if pings:
            return str(round(sum(pings[-20:]) / min(20, len(pings)), 2))
        return "-"

    def _scan_done(self, count):
        QMessageBox.information(
            self, 
            "Escaneo completado", 
            f"{count} hosts activos encontrados en la red local."
        )

    def _scan_error(self, message):
        QMessageBox.critical(self, "Error", message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setWindowIcon(QIcon("icono.png"))
    monitor = PingMonitor()
    monitor.setWindowIcon(QIcon("icono.png"))
    monitor.show()
    sys.exit(app.exec_())