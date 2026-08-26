from flask import Flask, request, jsonify, send_from_directory
import pickle, numpy as np, os, json

app = Flask(__name__, static_folder='static')

with open('xgboost_model.pkl', 'rb') as f:
    model = pickle.load(f)

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json()
    features = data.get('features')
    if not features or len(features) != 7:
        return jsonify({'error': 'Need 7 features'}), 400
    x = np.array([features], dtype=float)
    proba = model.predict_proba(x)[0]
    pred = int(model.predict(x)[0])
    return jsonify({
        'prediction': pred,
        'label': 'RANSOMWARE' if pred == 1 else 'BENIGN',
        'confidence': float(proba[pred]),
        'ransomware_prob': float(proba[1]),
        'benign_prob': float(proba[0])
    })

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)
