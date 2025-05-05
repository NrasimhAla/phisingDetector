# Import required libraries
from flask import Flask, request, render_template
import numpy as np
import pickle
import warnings
from convert import convertion
from feature import FeatureExtraction
from urllib.parse import urlparse
import csv
import joblib
import re
import pandas as pd

warnings.filterwarnings('ignore')

# Load trained model
with open("newmodel.pkl", "rb") as file:
    gbc = pickle.load(file)

# Initialize Flask app
app = Flask(__name__)

# Load legitimate URLs from CSV
def load_safe_domains():
    try:
        df = pd.read_csv('legitimateurls.csv')
        return set(df['url'].str.lower().tolist())
    except Exception as e:
        print(f"Error loading legitimate URLs: {e}")
        return set()

# Load safe domains
SAFE_DOMAINS = load_safe_domains()

def check_legitimate_url(url):
    """Check if URL is in legitimate URLs list"""
    try:
        with open('DataFiles/legitimateurls.csv', 'r') as file:
            reader = csv.reader(file)
            domain = urlparse(url).netloc.lower()
            for row in reader:
                if row[0].lower() in domain:
                    return True
        return False
    except:
        return False

def check_url_spoofing(url):
    """Check for URL spoofing attempts"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Common character substitutions used in spoofing
        substitutions = {
            '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's', '6': 'b', '7': 't', '8': 'b', '9': 'g'
        }
        
        # Check against legitimate domains
        with open('DataFiles/legitimateurls.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                safe_domain = row[0].lower()
                # Check for character substitutions
                substituted_domain = domain
                for old, new in substitutions.items():
                    substituted_domain = substituted_domain.replace(old, new)
                if substituted_domain == safe_domain:
                    return True
                    
                # Check for missing/extra characters
                if len(domain) >= len(safe_domain) - 1 and len(domain) <= len(safe_domain) + 1:
                    if sum(a != b for a, b in zip(domain, safe_domain)) <= 1:
                        return True
        return False
    except:
        return False

@app.route("/")
def home():
    return render_template("index.html")

@app.route('/result', methods=['POST', 'GET'])
def predict():
    if request.method == "POST":
        url = request.form["name"]
        
        # First check if URL is in legitimate list
        if check_legitimate_url(url):
            return render_template("index.html", name=convertion(url, 1))
            
        # Check for URL spoofing
        if check_url_spoofing(url):
            return render_template("index.html", name=convertion(url, -1))

        x = np.array(FeatureExtraction(url).getFeaturesList()).reshape(1, 30)

        # First get model prediction
        y_pred = gbc.predict(x)[0]
        
        # If model predicts phishing (-1), return phishing immediately
        if y_pred == -1:
            return render_template("index.html", name=convertion(url, -1))
            
        # If model predicts safe (1), check feature array
        if y_pred == 1:
            neg, zero, pos = np.sum(x == -1), np.sum(x == 0), np.sum(x == 1)
            total_features = neg + zero + pos
            feature_ratio = pos / total_features if total_features > 0 else 0
            
            # If less than 70% features are safe, mark as phishing
            if feature_ratio < 0.7:
                return render_template("index.html", name=convertion(url, -1))
            
            # If all checks pass, return safe
            return render_template("index.html", name=convertion(url, 1))

@app.route('/usecases', methods=['GET', 'POST'])
def usecases():
    return render_template('usecases.html')

if __name__ == "__main__":
    app.run(debug=True)
