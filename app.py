from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import pam
from functools import wraps
from config import Config
from vici_manager import ViciManager

app = Flask(__name__)
app.config.from_object(Config)

# Initialisation du gestionnaire Vici
try:
    vici_manager = ViciManager()
except Exception as e:
    print(f"ERREUR: {e}")
    vici_manager = None

def authenticate_pam(username, password):
    """Authentification via PAM"""
    try:
        p = pam.pam()
        return p.authenticate(username, password, service=Config.PAM_SERVICE)
    except Exception as e:
        print(f"Erreur PAM: {e}")
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Veuillez vous connecter', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def dashboard():
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return render_template('dashboard.html', connections=[], status={}, stats={})
    
    connections = vici_manager.get_connections()
    status = vici_manager.get_connection_status()
    stats = vici_manager.get_stats()
    
    return render_template('dashboard.html', 
                         connections=connections, 
                         status=status,
                         stats=stats)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Veuillez saisir un nom d\'utilisateur et un mot de passe', 'error')
            return render_template('login.html')
        
        if authenticate_pam(username, password):
            session['username'] = username
            session.permanent = True
            flash('Authentification réussie', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Échec de l\'authentification PAM', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))

@app.route('/connections')
@login_required
def connections():
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('dashboard'))
    
    connections_list = vici_manager.get_connections()
    return render_template('connections.html', connections=connections_list)

@app.route('/connections/create', methods=['GET', 'POST'])
@login_required
def create_connection():
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('connections'))
    
    if request.method == 'POST':
        config = {
            'name': request.form.get('name'),
            'left': request.form.get('left', '%any'),
            'leftsubnet': request.form.get('leftsubnet', '0.0.0.0/0'),
            'right': request.form.get('right', '%any'),
            'rightsubnet': request.form.get('rightsubnet', '0.0.0.0/0'),
            'ike': request.form.get('ike', 'aes256-sha256-modp2048'),
            'esp': request.form.get('esp', 'aes256-sha256'),
            'keyexchange': request.form.get('keyexchange', 'ikev2'),
            'auto': request.form.get('auto', 'start')
        }
        
        if vici_manager.create_connection(config):
            flash('Connexion créée avec succès', 'success')
            return redirect(url_for('connections'))
        else:
            flash('Erreur lors de la création', 'error')
    
    return render_template('edit_connection.html', connection=None)

@app.route('/connections/edit/<string:name>', methods=['GET', 'POST'])
@login_required
def edit_connection(name):
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('connections'))
    
    connection = vici_manager.load_connection(name)
    if not connection:
        flash('Connexion non trouvée', 'error')
        return redirect(url_for('connections'))
    
    if request.method == 'POST':
        config = {
            'name': request.form.get('name'),
            'left': request.form.get('left'),
            'leftsubnet': request.form.get('leftsubnet'),
            'right': request.form.get('right'),
            'rightsubnet': request.form.get('rightsubnet'),
            'ike': request.form.get('ike'),
            'esp': request.form.get('esp'),
            'keyexchange': request.form.get('keyexchange'),
            'auto': request.form.get('auto')
        }
        
        if vici_manager.update_connection(name, config):
            flash('Connexion modifiée avec succès', 'success')
            return redirect(url_for('connections'))
        else:
            flash('Erreur lors de la modification', 'error')
    
    return render_template('edit_connection.html', connection=connection)

@app.route('/connections/delete/<string:name>')
@login_required
def delete_connection(name):
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('connections'))
    
    if vici_manager.unload_connection(name):
        flash('Connexion supprimée', 'success')
    else:
        flash('Erreur lors de la suppression', 'error')
    
    return redirect(url_for('connections'))

@app.route('/connections/start/<string:name>')
@login_required
def start_connection(name):
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('dashboard'))
    
    if vici_manager.initiate_connection(name):
        flash(f'Connexion {name} démarrée', 'success')
    else:
        flash(f'Erreur démarrage {name}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/connections/stop/<string:name>')
@login_required
def stop_connection(name):
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('dashboard'))
    
    if vici_manager.terminate_connection(name):
        flash(f'Connexion {name} arrêtée', 'success')
    else:
        flash(f'Erreur arrêt {name}', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/reload-secrets')
@login_required
def reload_secrets():
    if not vici_manager:
        flash('Service StrongSwan indisponible', 'error')
        return redirect(url_for('dashboard'))
    
    if vici_manager.reload_secrets():
        flash('Secrets rechargés', 'success')
    else:
        flash('Erreur rechargement secrets', 'error')
    
    return redirect(url_for('dashboard'))

@app.route('/api/status')
@login_required
def api_status():
    if not vici_manager:
        return jsonify({})
    return jsonify(vici_manager.get_connection_status())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)