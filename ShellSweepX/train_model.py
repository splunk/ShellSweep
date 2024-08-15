"""
ShellSweepML - Webshell Detection Model Training Script
--------------------------------------------------------

Author: Mike Haag
Date: 08-10-2023
Version: 0.1

Description:
This script is designed to train a machine learning model for the purpose of detecting webshells in web server directories. 
It uses a logistic regression classifier and TF-IDF vectorization to process and classify the content of the files.

Features:
- Scans specified directories for potential webshell content.
- Uses the TF-IDF vectorization technique to convert file content into numerical data suitable for machine learning.
- Trains a logistic regression classifier using the vectorized data.
- Outputs a trained model (`model.pkl`) and a vectorizer (`vectorizer.pkl`) for use in prediction tasks.

Dependencies:
- scikit-learn
- joblib

Usage:
Simply run the script, and it will process the files in the defined directories, train the model, and save the resulting model and vectorizer.

Note:
Ensure that the directories containing potential webshells and benign files are correctly specified.

"""

import os
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib

# Define webshell directories
webshell_directories = [
    'C:/Users/Administrator/Desktop/MLHaag/Shells'
]

def extract_file_content(directory, file_list):
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_list.append(f.read())
            except PermissionError:
                print(f"Permission denied for file: {file_path}")
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

webshell_files = []
for directory in webshell_directories:
    extract_file_content(directory, webshell_files)

benign_files = []
extract_file_content('benign/', benign_files)

labels = [1] * len(webshell_files) + [0] * len(benign_files)

common_top_words = [
    "width", "td", "int", "value", "file", "void", "public", "tablecell", "if", "string"
]

vectorizer = TfidfVectorizer(max_features=5000, stop_words=common_top_words)
X = vectorizer.fit_transform(webshell_files + benign_files)

joblib.dump(vectorizer, 'vectorizer.pkl')

X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2)

clf = LogisticRegression()
clf.fit(X_train, y_train)

joblib.dump(clf, 'model.pkl')

