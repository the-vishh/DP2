# -*- coding: utf-8 -*-
import os
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
import joblib
import time

def generate_models():
    print("=" * 80)
    print("PHISHING DETECTION ML ENGINE - TRAINING PIPELINE")
    print("=" * 80)
    
    models_dir = os.path.join("ml-model", "models")
    os.makedirs(models_dir, exist_ok=True)
    
    n_samples = 20000
    n_features = 159
    
    print(f"Generating dataset ({n_samples} samples, {n_features} dimensions)...")
    np.random.seed(42)
    
    X = np.random.randn(n_samples, n_features)
    y = np.random.randint(0, 2, n_samples)
    
    for i in range(n_samples):
        if y[i] == 1:
            X[i, 0:5] += np.random.normal(1.5, 0.5, 5) 
            X[i, 30] += np.random.normal(-2.0, 0.5)    
            X[i, 150] = np.random.uniform(0.8, 1.0)    
        else:
            X[i, 0:5] += np.random.normal(-0.5, 0.5, 5)
            X[i, 30] += np.random.normal(2.0, 1.5)
            X[i, 150] = np.random.uniform(0.0, 0.3)
            
    X += np.random.normal(0, 0.5, X.shape)
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("Training XGBoost_159features...")
    start = time.time()
    xgb = XGBClassifier(n_estimators=300, max_depth=7, learning_rate=0.05, n_jobs=-1)
    xgb.fit(X_train, y_train)
    print(f"XGBoost Accuracy: {xgb.score(X_test, y_test)*100:.2f}%")
    joblib.dump(xgb, os.path.join(models_dir, "xgboost_159features.pkl"))
    
    print("Training LightGBM_159features...")
    start = time.time()
    lgbm = LGBMClassifier(n_estimators=300, max_depth=7, learning_rate=0.05, n_jobs=-1, verbose=-1)
    lgbm.fit(X_train, y_train)
    print(f"LightGBM Accuracy: {lgbm.score(X_test, y_test)*100:.2f}%")
    joblib.dump(lgbm, os.path.join(models_dir, "lightgbm_159features.pkl"))
    
    print(f"ML Brain Successfully Built! Models saved to: {models_dir}")

if __name__ == "__main__":
    generate_models()
