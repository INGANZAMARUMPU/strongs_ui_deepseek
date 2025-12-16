import subprocess
import vici
from typing import List, Dict, Optional

class ViciManager:
    def __init__(self):
        try:
            self.session = vici.Session()
        except Exception as e:
            raise Exception(f"Impossible de se connecter au socket Vici: {e}")

    def _parse_vici_response(self, response):
        """Parse la réponse Vici en dictionnaire"""
        if hasattr(response, 'items'):
            return {k: self._parse_vici_response(v) for k, v in response.items()}
        elif isinstance(response, (list, tuple)):
            return [self._parse_vici_response(item) for item in response]
        elif isinstance(response, bytes):
            return response.decode('utf-8')
        else:
            return response

    def get_connections(self) -> List[Dict]:
        """Récupère toutes les connexions configurées"""
        try:
            connections = []
            # Convertir le générateur en liste d'abord
            response = list(self.session.list_conns())
            
            for conn in response:
                parsed_conn = self._parse_vici_response(conn)
                if isinstance(parsed_conn, dict):
                    for conn_name, conn_config in parsed_conn.items():
                        connections.append({
                            'name': conn_name,
                            'config': conn_config
                        })
            
            return connections
        except Exception as e:
            print(f"Erreur list_conns: {e}")
            return []

    def get_sas(self) -> List[Dict]:
        """Récupère les Security Associations actives"""
        try:
            sas = []
            response = list(self.session.list_sas())
            
            for sa in response:
                parsed_sa = self._parse_vici_response(sa)
                if isinstance(parsed_sa, dict):
                    for sa_name, sa_config in parsed_sa.items():
                        sas.append({
                            'name': sa_name,
                            'config': sa_config
                        })
            
            return sas
        except Exception as e:
            print(f"Erreur list_sas: {e}")
            return []

    def get_connection_status(self) -> Dict[str, Dict]:
        """Récupère le statut détaillé des connexions"""
        status = {}
        
        try:
            sas = self.get_sas()
            connections = self.get_connections()
            
            # Marquer toutes comme non établies d'abord
            for conn in connections:
                status[conn['name']] = {
                    'state': 'non établie', 
                    'bytes_in': 0, 
                    'bytes_out': 0,
                    'established_time': 0,
                    'packets_in': 0,
                    'packets_out': 0
                }
            
            # Mettre à jour avec les SAs actives
            for sa in sas:
                conn_name = sa['name']
                if conn_name in status:
                    status[conn_name]['state'] = 'established'
                    status[conn_name]['established_time'] = int(sa['config'].get('established', 0))
                    
                    # Somme des bytes/packets de tous les child-sas
                    total_bytes_in = 0
                    total_bytes_out = 0
                    total_packets_in = 0
                    total_packets_out = 0
                    
                    if 'child-sas' in sa['config']:
                        for child_sa in sa['config']['child-sas'].values():
                            total_bytes_in += int(child_sa.get('bytes-in', 0))
                            total_bytes_out += int(child_sa.get('bytes-out', 0))
                            total_packets_in += int(child_sa.get('packets-in', 0))
                            total_packets_out += int(child_sa.get('packets-out', 0))
                    
                    status[conn_name]['bytes_in'] = total_bytes_in
                    status[conn_name]['bytes_out'] = total_bytes_out
                    status[conn_name]['packets_in'] = total_packets_in
                    status[conn_name]['packets_out'] = total_packets_out
                    
        except Exception as e:
            print(f"Erreur statut connexions: {e}")
        
        return status

    def load_connection(self, name: str) -> Optional[Dict]:
        """Charge une connexion spécifique"""
        connections = self.get_connections()
        for conn in connections:
            if conn['name'] == name:
                return conn
        return None

    def create_connection(self, config: Dict) -> bool:
        """Crée une nouvelle connexion"""
        try:
            vici_config = self._format_vici_config(config)
            self.session.load_conn(vici_config)
            
            # Si auto=start, on initie la connexion
            if config.get('auto') == 'start':
                self.initiate_connection(config['name'])
            
            return True
        except Exception as e:
            print(f"Erreur création connexion: {e}")
            return False

    def update_connection(self, old_name: str, new_config: Dict) -> bool:
        """Met à jour une connexion existante"""
        try:
            # Unload l'ancienne connexion
            self.unload_connection(old_name)
            
            # Crée la nouvelle
            return self.create_connection(new_config)
        except Exception as e:
            print(f"Erreur mise à jour connexion: {e}")
            return False

    def unload_connection(self, name: str) -> bool:
        """Supprime une connexion"""
        try:
            # Essaie d'abord de terminer la connexion si active
            try:
                self.session.terminate({'ike': name})
            except:
                pass
            
            # Puis unload
            self.session.unload_conn({'name': name})
            return True
        except Exception as e:
            print(f"Erreur suppression connexion: {e}")
            # Si ça échoue, essaie de recharger la config
            try:
                self.session.reload({'reload-settings': True})
                return True
            except:
                return False

    def initiate_connection(self, name: str) -> bool:
        """Démarre une connexion"""
        # try:
        #     self.session.initiate({'ike': name})
        #     return True
        # except Exception as e:
        #     print(f"Erreur initiation connexion: {e}")
        #     return False
        command_string = f"sudo ipsec up {name};"
        try:
            result = subprocess.run(
                command_string,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            print(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            print("STDOUT:", e.stdout)
            print("STDERR:", e.stderr)
            return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    def terminate_connection(self, name: str) -> bool:
        # """Arrête une connexion"""
        # try:
        #     self.session.terminate({'ike': name})
        #     return True
        # except Exception as e:
        #     print(f"Erreur terminaison connexion: {e}")
        #     return False
        command_string = f"sudo ipsec down {name};"
        try:
            result = subprocess.run(
                command_string,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            print(result.stdout)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Command failed with return code {e.returncode}")
            print("STDOUT:", e.stdout)
            print("STDERR:", e.stderr)
            return False
        except Exception as e:
            print(f"An error occurred: {e}")
            return False

    def get_stats(self) -> Dict:
        """Récupère les statistiques"""
        try:
            stats = self.session.stats()
            return self._parse_vici_response(stats)
        except Exception as e:
            print(f"Erreur stats: {e}")
            return {}

    def reload_secrets(self) -> bool:
        """Recharge les secrets PSK"""
        try:
            self.session.load_shared({})
            return True
        except Exception as e:
            print(f"Erreur reload secrets: {e}")
            return False

    def _format_vici_config(self, config: Dict) -> Dict:
        """Formate la configuration pour Vici"""
        vici_config = {
            config['name']: {
                'local_addrs': [config.get('left', '%any')],
                'remote_addrs': [config.get('right', '%any')],
                'version': '1' if config.get('keyexchange') == 'ikev1' else '2',
                'local': {
                    'auth': 'psk'
                },
                'remote': {
                    'auth': 'psk'
                },
                'children': {
                    config['name']: {
                        'local_ts': [config.get('leftsubnet', '0.0.0.0/0')],
                        'remote_ts': [config.get('rightsubnet', '0.0.0.0/0')],
                        'start_action': 'trap' if config.get('auto') == 'start' else 'none'
                    }
                }
            }
        }
        
        # Ajoute proposals seulement si spécifié et valide
        if config.get('ike'):
            vici_config[config['name']]['proposals'] = [config['ike']]
        
        if config.get('esp'):
            vici_config[config['name']]['children'][config['name']]['esp_proposals'] = [config['esp']]
        
        return vici_config