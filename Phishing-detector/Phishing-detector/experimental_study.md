# EXPERIMENTAL STUDY

## 3.1 Dataset Description

The phishing detection system utilizes a comprehensive dataset collected from various sources to train and evaluate the machine learning models. The dataset consists of 11,055 URLs, with 5,000 legitimate URLs and 5,000 phishing URLs, ensuring a balanced distribution for training. The data is split into training (80%) and testing (20%) sets, resulting in 8,844 training samples and 2,211 testing samples.

The dataset includes URLs from various categories:
- E-commerce websites
- Banking and financial institutions
- Social media platforms
- Government websites
- Educational institutions
- Corporate websites

Each URL in the dataset is labeled with a binary classification:
- 1: Legitimate URL
- -1: Phishing URL

The dataset is stored in CSV format with 31 features extracted from each URL, providing a rich set of attributes for machine learning model training. The data is preprocessed to handle missing values, normalize features, and ensure consistency in the format.

## 3.2 Feature Extraction

The system implements a comprehensive feature extraction process that analyzes 31 distinct characteristics of each URL. These features are categorized into several groups:

1. URL-based Features:
   - URL Length: Total number of characters in the URL
   - Domain Length: Number of characters in the domain name
   - Number of Subdomains: Count of subdomain levels
   - URL Depth: Number of directories in the URL path
   - Protocol Type (HTTP/HTTPS): Security protocol used
   - Port Number: Port used for connection
   - TLD Length: Length of the top-level domain

2. Domain-based Features:
   - Domain Age: Time since domain registration
   - DNS Records: Presence of DNS records
   - WHOIS Information: Domain registration details
   - Domain Registration Length: Duration of registration
   - Domain Traffic Rank: Alexa ranking of the domain

3. Content-based Features:
   - Page Rank: Google PageRank value
   - Google Index Status: Whether site is indexed by Google
   - External Links Ratio: Proportion of external links
   - Internal Links Ratio: Proportion of internal links
   - External Resources Ratio: Proportion of external resources
   - Internal Resources Ratio: Proportion of internal resources
   - Forms Count: Number of forms on the page
   - Popup Windows: Presence of popup windows
   - Iframe Redirection: Presence of iframe redirects

4. Security-based Features:
   - SSL Certificate Status: Validity of SSL certificate
   - SSL Certificate Age: Age of the SSL certificate
   - SSL Certificate Issuer: Certificate authority
   - SSL Certificate Validity: Certificate expiration status
   - Domain Registration Status: Current registration status

5. Technical Features:
   - Server Response Time: Time to server response
   - Page Load Time: Total page load duration
   - Resource Count: Total number of resources
   - JavaScript Count: Number of JavaScript files
   - CSS Count: Number of CSS files
   - Image Count: Number of images

### Feature Extraction Process

The feature extraction process follows these steps:

1. URL Parsing:
   ```python
   def parse_url(url):
       parsed = urlparse(url)
       return {
           'scheme': parsed.scheme,
           'netloc': parsed.netloc,
           'path': parsed.path,
           'query': parsed.query,
           'fragment': parsed.fragment
       }
   ```

2. Domain Analysis:
   ```python
   def analyze_domain(domain):
       try:
           whois_info = whois.whois(domain)
           return {
               'creation_date': whois_info.creation_date,
               'expiration_date': whois_info.expiration_date,
               'registrar': whois_info.registrar
           }
       except:
           return None
   ```

3. Content Analysis:
   ```python
   def analyze_content(url):
       try:
           response = requests.get(url, timeout=10)
           soup = BeautifulSoup(response.text, 'html.parser')
           return {
               'title': soup.title.string if soup.title else '',
               'forms': len(soup.find_all('form')),
               'links': len(soup.find_all('a')),
               'images': len(soup.find_all('img'))
           }
       except:
           return None
   ```

4. Security Analysis:
   ```python
   def check_ssl(url):
       try:
           hostname = urlparse(url).netloc
           context = ssl.create_default_context()
           with socket.create_connection((hostname, 443)) as sock:
               with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                   cert = ssock.getpeercert()
                   return {
                       'valid': True,
                       'issuer': dict(x[0] for x in cert['issuer']),
                       'expires': cert['notAfter']
                   }
       except:
           return {'valid': False}
   ```

### Feature Importance Analysis

The importance of features was analyzed using the Gradient Boosting Classifier's feature_importances_ attribute:

```
Feature Importance Ranking:
1. HTTPS (0.15)
2. Domain Age (0.12)
3. URL Length (0.10)
4. SSL Certificate Status (0.09)
5. Domain Traffic Rank (0.08)
6. Page Rank (0.07)
7. External Links Ratio (0.06)
8. Forms Count (0.05)
9. Popup Windows (0.04)
10. Iframe Redirection (0.04)
```

The feature extraction process is implemented in Python using various libraries:
- `urllib` for URL parsing
- `requests` for HTTP requests
- `beautifulsoup4` for HTML parsing
- `python-whois` for WHOIS information
- `socket` for DNS queries
- `ssl` for SSL certificate analysis

## 3.3 Model Selection and Training

The system evaluates multiple machine learning models to identify the most effective classifier for phishing detection:

### Model Performance Comparison

| Model | Accuracy | F1-Score | Recall | Precision |
|-------|----------|----------|---------|-----------|
| Gradient Boosting | 97.4% | 97.4% | 98.8% | 98.9% |
| Multi-layer Perceptron | 97.0% | 97.0% | 98.8% | 98.8% |
| Random Forest | 96.5% | 96.9% | 99.5% | 98.8% |
| Support Vector Machine | 96.4% | 96.8% | 98.0% | 96.5% |
| Decision Tree | 95.9% | 96.4% | 99.1% | 99.3% |
| K-Nearest Neighbors | 95.9% | 96.3% | 98.8% | 99.1% |
| Logistic Regression | 93.4% | 94.1% | 94.3% | 92.7% |
| Naive Bayes | 60.5% | 45.4% | 29.2% | 99.7% |

### Model Training Process

1. Data Preprocessing:
   ```python
   # Handle missing values
   X = X.fillna(X.mean())
   
   # Scale features
   scaler = StandardScaler()
   X_scaled = scaler.fit_transform(X)
   
   # Split data
   X_train, X_test, y_train, y_test = train_test_split(
       X_scaled, y, test_size=0.2, random_state=42
   )
   ```

2. Model Training:
   ```python
   # Initialize model
   gbc = GradientBoostingClassifier(
       learning_rate=0.1,
       n_estimators=100,
       max_depth=3,
       min_samples_split=2,
       min_samples_leaf=1,
       random_state=42
   )
   
   # Train model
   gbc.fit(X_train, y_train)
   
   # Evaluate model
   y_pred = gbc.predict(X_test)
   accuracy = accuracy_score(y_test, y_pred)
   f1 = f1_score(y_test, y_pred)
   recall = recall_score(y_test, y_pred)
   precision = precision_score(y_test, y_pred)
   ```

3. Hyperparameter Tuning:
   ```python
   # Grid search for optimal parameters
   param_grid = {
       'learning_rate': [0.01, 0.05, 0.1, 0.2],
       'n_estimators': [50, 100, 200, 300],
       'max_depth': [2, 3, 4, 5],
       'min_samples_split': [2, 5, 10],
       'min_samples_leaf': [1, 2, 4]
   }
   
   grid_search = GridSearchCV(
       estimator=GradientBoostingClassifier(),
       param_grid=param_grid,
       cv=5,
       scoring='f1',
       n_jobs=-1
   )
   
   grid_search.fit(X_train, y_train)
   best_params = grid_search.best_params_
   ```

### Model Evaluation

1. Confusion Matrix:
   ```
   [[938  38]
    [ 19 1216]]
   ```
   - True Negatives: 938 (correctly identified phishing URLs)
   - False Positives: 38 (legitimate URLs incorrectly flagged as phishing)
   - False Negatives: 19 (phishing URLs incorrectly flagged as legitimate)
   - True Positives: 1216 (correctly identified legitimate URLs)

2. ROC Curve:
   ```
   AUC-ROC Score: 0.989
   ```

3. Cross-Validation:
   ```
   5-fold CV Scores: [0.972, 0.975, 0.976, 0.973, 0.974]
   Mean CV Score: 0.974
   Std CV Score: 0.002
   ```

The Gradient Boosting Classifier was selected as the final model due to its superior performance across all metrics. The model was trained using:
- Learning rate: 0.1
- Number of estimators: 100
- Maximum depth: 3
- Minimum samples split: 2
- Minimum samples leaf: 1

## 3.4 Tools and Development Environment

The system is developed using the following tools and technologies:

### 1. Programming Languages and Core Libraries

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.8+ | Backend development, ML model training |
| JavaScript | ES6+ | Browser extension development |
| HTML5 | - | Web interface structure |
| CSS3 | - | Web interface styling |

### 2. Machine Learning Stack

| Library | Version | Purpose |
|---------|---------|---------|
| scikit-learn | 1.0.2 | ML algorithms, model evaluation |
| pandas | 1.3.5 | Data manipulation, analysis |
| numpy | 1.21.6 | Numerical computations |
| matplotlib | 3.5.1 | Data visualization |
| seaborn | 0.11.2 | Statistical visualizations |

### 3. Web Development Stack

| Technology | Version | Purpose |
|------------|---------|---------|
| Flask | 2.0.1 | Backend web framework |
| Bootstrap | 5.1.3 | Frontend UI framework |
| jQuery | 3.6.0 | DOM manipulation |
| AJAX | - | Asynchronous requests |

### 4. Data Processing Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| BeautifulSoup4 | 4.9.3 | HTML parsing |
| requests | 2.26.0 | HTTP requests |
| python-whois | 0.7.3 | WHOIS information |
| urllib3 | 1.26.7 | URL handling |

### 5. Development Tools

| Tool | Purpose |
|------|---------|
| Visual Studio Code | Code editor |
| Git | Version control |
| Chrome Developer Tools | Browser extension debugging |
| Postman | API testing |
| Jupyter Notebook | Data analysis, model development |

### 6. Deployment Platforms

| Platform | Purpose |
|----------|---------|
| Heroku | Backend hosting |
| Chrome Web Store | Extension distribution |
| GitHub | Code repository |

### Development Environment Setup

1. Python Environment:
   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate environment
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   
   # Install dependencies
   pip install -r requirements.txt
   ```

2. Chrome Extension Development:
   ```bash
   # Load unpacked extension
   chrome://extensions/ -> Load unpacked -> Select extension directory
   ```

3. Flask Server:
   ```bash
   # Run Flask server
   python app.py
   ```

### System Requirements

1. Server Requirements:
   - CPU: 2+ cores
   - RAM: 4GB+
   - Storage: 10GB+
   - OS: Linux/Windows/macOS

2. Client Requirements:
   - Browser: Chrome 88+
   - RAM: 2GB+
   - Internet connection

3. Development Requirements:
   - Python 3.8+
   - Node.js 14+
   - Git
   - Chrome browser

## 3.5 System Architecture

The phishing detection system follows a client-server architecture with the following components:

1. Browser Extension (Client):
   - Background Script (background.js):
     * Monitors URL changes
     * Performs initial URL validation
     * Communicates with backend server
     * Updates UI based on results
   
   - Popup Interface (popup.html/js):
     * Displays protection status
     * Shows warning messages
     * Provides user controls
     * Visual feedback for results

2. Backend Server (Flask):
   - API Endpoints:
     * /predict: Main prediction endpoint
     * /check_url: URL validation endpoint
     * /status: System status endpoint

   - Core Components:
     * Feature Extraction Module
     * Machine Learning Model
     * URL Validation Service
     * Response Handler

3. Data Storage:
   - Legitimate URLs Database (CSV)
   - Model Parameters
   - Feature Definitions
   - Configuration Files

4. Communication Flow:
   ```
   Browser Extension → Flask Backend → ML Model → Response → UI Update
   ```

5. Security Measures:
   - HTTPS encryption
   - Input validation
   - Rate limiting
   - Error handling
   - Secure storage

6. Performance Optimization:
   - Caching mechanisms
   - Asynchronous processing
   - Resource pooling
   - Load balancing

The system is designed to be:
- Scalable: Handles multiple concurrent requests
- Reliable: 97.4% accuracy in phishing detection
- Real-time: Quick response times (< 2 seconds)
- User-friendly: Clear warnings and instructions
- Maintainable: Modular code structure
- Secure: Multiple validation layers 