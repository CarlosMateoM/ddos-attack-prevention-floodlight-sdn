import requests
import json
import time
from collections import defaultdict
import threading

class FloodlightDDoSDetector:
    def __init__(self, controller_ip='127.0.0.1', controller_port=8080):
        self.base_url = f'http://{controller_ip}:{controller_port}'
        self.ip_records = defaultdict(lambda: {'count': 0, 'first_seen': 0, 'last_seen': 0})
        self.blocked_ips = set()
        
        # Configuración
        self.PACKET_THRESHOLD = 1000  # paquetes por segundo
        self.MONITORING_INTERVAL = 1  # segundos
        
        # Iniciar thread de monitoreo
        self.monitor_thread = threading.Thread(target=self.monitor_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    def get_switches(self):
        """Obtiene lista de switches conectados al controlador"""
        response = requests.get(f'{self.base_url}/wm/core/controller/switches/json')
        return response.json()

    def get_flows(self, switch_id):
        """Obtiene flujos de un switch específico"""
        response = requests.get(f'{self.base_url}/wm/core/switch/{switch_id}/flow/json')
        return response.json()

    def add_flow(self, switch_id, flow_rule):
        """Agrega una regla de flujo a un switch"""
        url = f'{self.base_url}/wm/staticentrypusher/json'
        response = requests.post(url, json=flow_rule)
        return response.status_code == 200

    def block_ip(self, switch_id, ip_address):
        """Bloquea una IP específica en un switch"""
        if ip_address in self.blocked_ips:
            return
        
        flow_rule = {
            "switch": switch_id,
            "name": f"block_ip_{ip_address}",
            "cookie": "0",
            "priority": "32768",
            "eth_type": "0x800",  # IPv4
            "ipv4_src": ip_address,
            "active": "true",
            "actions": ""  # Sin acciones = descartar paquetes
        }

        if self.add_flow(switch_id, flow_rule):
            print(f"IP bloqueada: {ip_address} en switch {switch_id}")
            self.blocked_ips.add(ip_address)

    def monitor_traffic(self):
        """Thread principal de monitoreo"""
        while True:
            try:
                # Obtener switches
                switches = self.get_switches()
                
                for switch in switches:
                    switch_id = switch['switchDPID']
                    flows = self.get_flows(switch_id)
                    
                    # Analizar flujos
                    self.analyze_flows(switch_id, flows)
                    
                # Limpiar registros antiguos
                self.cleanup_old_records()
                
                # Esperar intervalo de monitoreo
                time.sleep(self.MONITORING_INTERVAL)
                
            except Exception as e:
                print(f"Error en monitoreo: {e}")
                time.sleep(5)  # Esperar antes de reintentar

    def analyze_flows(self, switch_id, flows):
        """Analiza los flujos para detectar posibles ataques DDoS"""
        current_time = time.time()
        
        for flow in flows.get('flows', []):
            try:
                match = flow.get('match', {})
                ip_src = match.get('ipv4_src')
                
                if not ip_src or ip_src in self.blocked_ips:
                    continue
                
                # Actualizar registros
                if ip_src not in self.ip_records:
                    self.ip_records[ip_src] = {
                        'count': 1,
                        'first_seen': current_time,
                        'last_seen': current_time
                    }
                else:
                    record = self.ip_records[ip_src]
                    record['count'] += int(flow.get('packet_count', 1))
                    record['last_seen'] = current_time
                    
                    # Verificar umbral
                    if self.is_attack_detected(record):
                        self.block_ip(switch_id, ip_src)
                
            except Exception as e:
                print(f"Error analizando flujo: {e}")

    def is_attack_detected(self, record):
        """Determina si un patrón de tráfico indica un ataque DDoS"""
        current_time = time.time()
        duration = current_time - record['first_seen']
        
        if duration == 0:
            return False
            
        packets_per_second = record['count'] / duration
        return packets_per_second > self.PACKET_THRESHOLD

    def cleanup_old_records(self):
        """Limpia registros antiguos"""
        current_time = time.time()
        to_remove = []
        
        for ip, record in self.ip_records.items():
            if current_time - record['last_seen'] > 300:  # 5 minutos
                to_remove.append(ip)
                
        for ip in to_remove:
            del self.ip_records[ip]

    def get_statistics(self):
        """Retorna estadísticas actuales"""
        return {
            'monitored_ips': len(self.ip_records),
            'blocked_ips': len(self.blocked_ips),
            'blocked_list': list(self.blocked_ips)
        }

# Script de ejemplo de uso
if __name__ == "__main__":
    # Crear instancia del detector
    detector = FloodlightDDoSDetector()
    
    try:
        while True:
            # Mostrar estadísticas cada 10 segundos
            stats = detector.get_statistics()
            print("\nEstadísticas de DDoS:")
            print(f"IPs monitoreadas: {stats['monitored_ips']}")
            print(f"IPs bloqueadas: {stats['blocked_ips']}")
            print("IPs bloqueadas:", stats['blocked_list'])
            time.sleep(10)
            
    except KeyboardInterrupt:
        print("\nDetector detenido")