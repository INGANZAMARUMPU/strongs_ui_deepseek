import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'strongswan-manager-secret-key-2024'
    VICI_SOCKET = '/var/run/charon.vici'
    SESSION_TIMEOUT = 1800
    PAM_SERVICE = 'system-auth'