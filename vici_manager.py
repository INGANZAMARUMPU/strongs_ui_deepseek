import vici
from typing import List, Dict, Optional

class ViciManager:
    def __init__(self):
        try:
            self.session = vici.Session()
        except Exception as e:
            raise Exception(f"Impossible de se connecter au socket Vici: {e}")

    def _decode_value(self, value):
        """Décode les valeurs bytes en string"""
        if isinstance(value, bytes):
            return value.decode('utf-8')
        elif isinstance(value, dict):
            return {self._decode_value(k): self._decode_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._decode_value(item) for item in value]
        else:
            return value

    def get_connections(self) -> List[Dict]:
        """Récupère toutes les connexions configurées"""
        try:
            connections = []
            response = self.session.list_conns()
            
            for conn_name, conn_config in response.items():
                conn_name_decoded = self._decode_value(conn_name)
                conn_config_decoded = self._decode_value(conn_config)
                
                connections.append({
                    'name': conn_name_decoded,
                    'config': conn_config_decoded
                })
            
            return connections
        except Exception as e:
            print(f"Erreur list_conns: {e}")
            return []

    def get_sas(self) -> List[Dict]:
        """Récupère les Security Associations actives"""
        try:
            sas = []
            response = self.session.list_sas()
            
            for sa_name, sa_config in response.items():
                sa_name_decoded = self._decode_value(sa_name)
                sa_config_decoded = self._decode_value(sa_config)
                
                sas.append({
                    'name': sa_name_decoded,
                    'config': sa_config_decoded
                })
            
            return sas
        except Exception as e:
            print(f"Erreur list_sas: {e}")
            return []

    def get_connection_status(self) -> Dict[str, str]:
        """Récupère le statut de chaque connexion"""
        status = {}
        
        # Récupère toutes les connexions configurées
        connections = self.get_connections()
        for conn in connections:
            status[conn['name']] = 'non établie'
        
        # Met à jour avec les SAs actives
        sas = self.get_sas()
        for sa in sas:
            state = sa['config'].get('state', 'unknown')
            status[sa['name']] = state
        
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
            self.session.unload_conn({'name': old_name})
            
            # Crée la nouvelle
            return self.create_connection(new_config)
        except Exception as e:
            print(f"Erreur mise à jour connexion: {e}")
            return False

    def unload_connection(self, name: str) -> bool:
        """Supprime une connexion"""
        try:
            self.session.unload_conn({'name': name})
            return True
        except Exception as e:
            print(f"Erreur suppression connexion: {e}")
            return False

    def initiate_connection(self, name: str) -> bool:
        """Démarre une connexion"""
        try:
            response = self.session.initiate({'ike': name})
            return True
        except Exception as e:
            print(f"Erreur initiation connexion: {e}")
            return False

    def terminate_connection(self, name: str) -> bool:
        """Arrête une connexion"""
        try:
            self.session.terminate({'ike': name})
            return True
        except Exception as e:
            print(f"Erreur terminaison connexion: {e}")
            return False

    def get_stats(self) -> Dict:
        """Récupère les statistiques"""
        try:
            stats = self.session.stats()
            return self._decode_value(stats)
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
                'proposals': [config.get('ike', 'aes256-sha256-modp2048')],
                'local': {
                    'auth': 'psk'
                },
                'remote': {
                    'auth': 'psk'
                },
                'children': {
                    f"{config['name']}-child": {
                        'local_ts': [config.get('leftsubnet', '0.0.0.0/0')],
                        'remote_ts': [config.get('rightsubnet', '0.0.0.0/0')],
                        'esp_proposals': [config.get('esp', 'aes256-sha256')],
                        'start_action': 'trap' if config.get('auto') == 'start' else 'none'
                    }
                }
            }
        }
        return vici_config