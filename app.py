
import joblib
import numpy as np
import pandas as pd
from flask import Flask, request, jsonify

app = Flask(__name__)

# Chargement des fichiers sauvegardés au démarrage du serveur
model        = joblib.load('model.pkl')
preprocessor = joblib.load('preprocessor.pkl')

# Les colonnes dans le bon ordre — exactement comme pendant l'entraînement
COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count',
    'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'message' : 'IDS API — Détection d intrusion NSL-KDD',
        'modele'  : 'Random Forest',
        'endpoint': '/predict'
    })

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Récupérer les données envoyées en JSON
        data = request.get_json()

        # Convertir en DataFrame avec les bonnes colonnes
        df = pd.DataFrame([data], columns=COLUMNS)

        # Appliquer le prétraitement
        df_processed = preprocessor.transform(df)

        # Prédire
        prediction = model.predict(df_processed)[0]
        probabilite = model.predict_proba(df_processed)[0]

        return jsonify({
            'prediction'  : int(prediction),
            'label'       : 'ATTAQUE' if prediction == 1 else 'NORMAL',
            'confiance'   : round(float(max(probabilite)) * 100, 2)
        })

    except Exception as e:
        return jsonify({'erreur': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
