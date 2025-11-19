from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import pwd
import spwd
import crypt
from functools import wraps
from config import Config
from vici_manager import ViciManager

app = Flask(__name__)
app.config.from_object(Config)

# Initialisation du gestionnaire Vici
vici_manager = ViciManager()

def authenticate_system_user(username, password):
    """Authentifie l'utilisateur avec les credentials système"""
    try:
        # Vérifie si l'utilisateur existe
        user_info = pwd.getpwnam(username)
        
        # Récupère les informations de shadow si disponibles
        try:
            shadow_info = spwd.getspnam(username)
            encrypted_password = shadow_info.sp_pwd
        except (KeyError, PermissionError):
            # Fallback sur /etc/passwd
            encrypted_password = user_info.pw_passwd
        
        # Vérifie le mot de passe
        if encrypted_password in ['x', '*']:
            return False  # Le mot de passe est dans shadow mais inaccessible
        
        return crypt.crypt(password, encrypted_password) == encrypted_password
        
    except (KeyError, ValueError):
        return False

def login_required(f):
    """Décorateur pour les pages nécessitant une authentification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def dashboard():
    """Page d'accueil avec le statut des connexions"""
    connections = vici_manager.get_connections()
    status = vici_manager.get_connection_status()
    stats = vici_manager.get_stats()
    
    return render_template('dashboard.html', 
                         connections=connections, 
                         status=status,
                         stats=stats,
                         username=session.get('username'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if authenticate_system_user(username, password):
            session['username'] = username
            session.permanent = True
            flash('Connexion réussie!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))

@app.route('/connections')
@login_required
def connections():
    """Page de gestion des connexions"""
    connections_list = vici_manager.get_connections()
    return render_template('connections.html', 
                         connections=connections_list,
                         username=session.get('username'))

@app.route('/connections/create', methods=['GET', 'POST'])
@login_required
def create_connection():
    """Création d'une nouvelle connexion"""
    if request.method == 'POST':
        name = request.form.get('name')
        left = request.form.get('left')
        leftsubnet = request.form.get('leftsubnet')
        right = request.form.get('right')
        rightsubnet = request.form.get('rightsubnet')
        ike = request.form.get('ike', 'aes256-sha256-modp2048')
        esp = request.form.get('esp', 'aes256-sha256')
        keyexchange = request.form.get('keyexchange', 'ikev2')
        auto = request.form.get('auto', 'start')
        
        config = {
            'name': name,
            'left': left,
            'leftsubnet': leftsubnet,
            'right': right,
            'rightsubnet': rightsubnet,
            'ike': ike,
            'esp': esp,
            'keyexchange': keyexchange,
            'auto': auto
        }
        
        if vici_manager.create_connection(config):
            flash('Connexion créée avec succès', 'success')
            return redirect(url_for('connections'))
        else:
            flash('Erreur lors de la création de la connexion', 'error')
    
    return render_template('edit_connection.html', 
                         connection=None,
                         username=session.get('username'))

@app.route('/connections/edit/<string:name>', methods=['GET', 'POST'])
@login_required
def edit_connection(name):
    """Modification d'une connexion existante"""
    connection = vici_manager.load_connection(name)
    
    if not connection:
        flash('Connexion non trouvée', 'error')
        return redirect(url_for('connections'))
    
    if request.method == 'POST':
        new_name = request.form.get('name')
        left = request.form.get('left')
        leftsubnet = request.form.get('leftsubnet')
        right = request.form.get('right')
        rightsubnet = request.form.get('rightsubnet')
        ike = request.form.get('ike')
        esp = request.form.get('esp')
        keyexchange = request.form.get('keyexchange')
        auto = request.form.get('auto')
        
        config = {
            'name': new_name,
            'left': left,
            'leftsubnet': leftsubnet,
            'right': right,
            'rightsubnet': rightsubnet,
            'ike': ike,
            'esp': esp,
            'keyexchange': keyexchange,
            'auto': auto
        }
        
        if vici_manager.update_connection(name, config):
            flash('Connexion modifiée avec succès', 'success')
            return redirect(url_for('connections'))
        else:
            flash('Erreur lors de la modification de la connexion', 'error')
    
    return render_template('edit_connection.html', 
                         connection=connection,
                         username=session.get('username'))

@app.route('/connections/delete/<string:name>')
@login_required
def delete_connection(name):
    """Suppression d'une connexion"""
    if vici_manager.unload_connection(name):
        flash('Connexion supprimée avec succès', 'success')
    else:
        flash('Erreur lors de la suppression de la connexion', 'error')
    
    return redirect(url_for('connections'))

@app.route('/connections/start/<string:name>')
@login_required
def start_connection(name):
    """Démarrage d'une connexion"""
    if vici_manager.initiate_connection(name):
        flash(f'Connexion {name} démarrée avec succès', 'success')
    else:
        flash(f'Erreur lors du démarrage de la connexion {name}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/connections/stop/<string:name>')
@login_required
def stop_connection(name):
    """Arrêt d'une connexion"""
    if vici_manager.terminate_connection(name):
        flash(f'Connexion {name} arrêtée avec succès', 'success')
    else:
        flash(f'Erreur lors de l\'arrêt de la connexion {name}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api/status')
@login_required
def api_status():
    """API pour récupérer le statut en temps réel"""
    status = vici_manager.get_connection_status()
    return jsonify(status)

@app.route('/api/stats')
@login_required
def api_stats():
    """API pour récupérer les statistiques"""
    stats = vici_manager.get_stats()
    return jsonify(stats)

@app.route('/reload-secrets')
@login_required
def reload_secrets():
    """Rechargement des secrets"""
    if vici_manager.reload_secrets():
        flash('Secrets rechargés avec succès', 'success')
    else:
        flash('Erreur lors du rechargement des secrets', 'error')
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)