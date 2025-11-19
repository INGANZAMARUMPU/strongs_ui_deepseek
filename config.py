import os
from dataclasses import dataclass

@dataclass
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'votre-cle-secrete-tres-secure'
    VICI_SOCKET = '/var/run/charon.vici'
    SESSION_TIMEOUT = 1800