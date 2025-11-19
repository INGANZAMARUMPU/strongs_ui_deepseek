import vici
from typing import List, Dict, Optional

class ViciManager:
    def __init__(self):
        self.session = vici.Session()
    
    def get_connections(self) -> List[Dict]:
        """Récupère la liste des connexions configurées"""
        try:
            connections = []
            response = self.session.list_conns()
            
            for conn_name, conn_config in response.items():
                connections.append({
                    'name': conn_name.decode() if isinstance(conn_name, bytes) else conn_name,
                    'config': self._decode_config(conn_config)
                })
            
            return connections
        except Exception as e:
            print(f"Erreur lors de la récupération des connexions: {e}")
            return []
    
    def get_sas(self) -> List[Dict]:
        """Récupère les Security Associations actives"""
        try:
            sas = []
            response = self.session.list_sas()
            
            for sa_name, sa_config in response.items():
                sas.append({
                    'name': sa_name.decode() if isinstance(sa_name, bytes) else sa_name,
                    'config': self._decode_config(sa_config)
                })
            
            return sas
        except Exception as e:
            print(f"Erreur lors de la récupération des SAs: {e}")
            return []
    
    def get_connection_status(self) -> Dict:
        """Récupère le statut des connexions"""
        status = {}
        try:
            sas = self.get_sas()
            connections = self.get_connections()
            
            # Marque toutes les connexions comme non établies
            for conn in connections:
                status[conn['name']] = 'non établie'
            
            # Met à jour le statut pour les SAs actives
            for sa in sas:
                conn_name = sa['name']
                state = sa['config'].get('state', 'inconnu')
                status[conn_name] = state
            
            return status
        except Exception as e:
            print(f"Erreur lors de la récupération du statut: {e}")
            return {}
    
    def _decode_config(self, config):
        """Décode la configuration bytes en strings"""
        decoded = {}
        for key, value in config.items():
            key_str = key.decode() if isinstance(key, bytes) else key
            
            if isinstance(value, bytes):
                decoded[key_str] = value.decode()
            elif isinstance(value, dict):
                decoded[key_str] = self._decode_config(value)
            elif isinstance(value, list):
                decoded[key_str] = [item.decode() if isinstance(item, bytes) else item for item in value]
            else:
                decoded[key_str] = value
        
        return decoded
    
    def load_connection(self, name: str) -> Optional[Dict]:
        """Charge une connexion spécifique"""
        try:
            connections = self.get_connections()
            for conn in connections:
                if conn['name'] == name:
                    return conn
            return None
        except Exception as e:
            print(f"Erreur lors du chargement de la connexion: {e}")
            return None
    
    def create_connection(self, config: Dict) -> bool:
        """Crée une nouvelle connexion IPsec"""
        try:
            # Formatte la configuration pour Vici
            vici_config = self._format_connection_config(config)
            
            # Charge la connexion
            self.session.load_conn(vici_config)
            
            # Initie la connexion si auto=start
            if config.get('auto') == 'start':
                self.session.initiate({'ike': config['name']})
            
            return True
            
        except Exception as e:
            print(f"Erreur lors de la création de la connexion: {e}")
            return False
    
    def update_connection(self, old_name: str, new_config: Dict) -> bool:
        """Met à jour une connexion existante"""
        try:
            # Supprime l'ancienne connexion
            self.unload_connection(old_name)
            
            # Crée la nouvelle connexion
            return self.create_connection(new_config)
            
        except Exception as e:
            print(f"Erreur lors de la mise à jour de la connexion: {e}")
            return False
    
    def unload_connection(self, name: str) -> bool:
        """Décharge une connexion"""
        try:
            self.session.unload_conn({'name': name})
            return True
        except Exception as e:
            print(f"Erreur lors du déchargement de la connexion: {e}")
            return False
    
    def terminate_connection(self, name: str) -> bool:
        """Termine une connexion active"""
        try:
            self.session.terminate({'ike': name})
            return True
        except Exception as e:
            print(f"Erreur lors de la terminaison de la connexion: {e}")
            return False
    
    def initiate_connection(self, name: str) -> bool:
        """Initie une connexion"""
        try:
            response = self.session.initiate({'ike': name})
            return response.get(b'success') is not None
        except Exception as e:
            print(f"Erreur lors de l'initiation de la connexion: {e}")
            return False
    
    def _format_connection_config(self, config: Dict) -> Dict:
        """Formate la configuration pour l'API Vici"""
        vici_config = {
            config['name']: {
                'local_addrs': [config.get('left', '%any')],
                'remote_addrs': [config.get('right', '%any')],
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
        
        # Ajoute les propositions IKE si spécifiées
        if 'ike' in config:
            vici_config[config['name']]['proposals'] = [config['ike']]
        
        # Ajoute keyexchange si spécifié
        if config.get('keyexchange') == 'ikev1':
            vici_config[config['name']]['version'] = '1'
        else:
            vici_config[config['name']]['version'] = '2'
        
        return vici_config
    
    def get_stats(self) -> Dict:
        """Récupère les statistiques"""
        try:
            stats = self.session.stats()
            return self._decode_config(stats)
        except Exception as e:
            print(f"Erreur lors de la récupération des statistiques: {e}")
            return {}
    
    def reload_secrets(self) -> bool:
        """Recharge les secrets"""
        try:
            self.session.load_shared({})
            return True
        except Exception as e:
            print(f"Erreur lors du rechargement des secrets: {e}")
            return False