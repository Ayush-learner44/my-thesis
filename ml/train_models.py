"""
============================================================
P4M3 Machine Learning Model Training Script
============================================================

Trains the EXACT ensemble described in the paper:
- K-Nearest Neighbors (KNN)
- Random Forest (RF)
- Decision Tree (DT)
- XGBoost
- Support Vector Machine (SVM)
- Majority vote ensemble

Feature used: Flow Packets/s (maps to PPS calculated in
controller from 20-packet window)

Paper Table I targets:
  SVM:         Precision=0.983, Recall=0.845, F1=0.901
  XGBoost:     Precision=0.981, Recall=0.929, F1=0.953
  KNN:         Precision=0.985, Recall=0.932, F1=0.958
  RF:          Precision=0.991, Recall=0.934, F1=0.960
  DT:          Precision=0.990, Recall=0.934, F1=0.960
  Models Vote: Precision=0.992, Recall=0.935, F1=0.961

USAGE:
  python3 train_models.py --csv /path/to/Syn.csv

OUTPUT:
  ml/models/knn_model.pkl
  ml/models/rf_model.pkl
  ml/models/dt_model.pkl
  ml/models/xgb_model.pkl
  ml/models/svm_model.pkl
  ml/models/scaler.pkl
============================================================
"""

import os
import sys
import argparse
import pickle
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score
from xgboost import XGBClassifier

# ============================================================
# CONFIGURATION
# ============================================================

# Feature columns from CIC-DDoS2019 SYN flood CSV that map to
# what the controller can calculate from a 20-packet window.
#
# Primary feature: Flow Packets/s
# This maps directly to PPS = 20 / (t_last - t_first)
# calculated in the controller's 20-packet window.
#
# We include a few supporting features for better accuracy
# but PPS is the dominant signal.
FEATURE_COLS = [
    ' Flow Packets/s',        # PRIMARY: maps to controller PPS
    ' Fwd Packets/s',         # maps to forward packet rate
    ' Fwd IAT Mean',          # inter-arrival time (inverse of PPS)
    ' Flow IAT Mean',         # overall inter-arrival time
    ' Total Fwd Packets',     # maps to window packet count
]

LABEL_COL = ' Label'

# Binary label: 'Syn' = attack (1), 'BENIGN' = benign (0)
ATTACK_LABEL = 'Syn'
BENIGN_LABEL = 'BENIGN'

# Balanced sample size to avoid bias
# Kaggle file has 158k+ attack, only 392 benign
# University file has more benign - sample 50k each if enough
MAX_SAMPLES_PER_CLASS = 50000

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'models')

# ============================================================
# LOAD AND PREPARE DATA
# ============================================================

def load_data(csv_path):
    print(f"\n[1/6] Loading dataset from: {csv_path}")
    print("      This may take a minute for large files...")

    df = pd.read_csv(csv_path, low_memory=False)
    print(f"      Loaded {len(df):,} rows, {len(df.columns)} columns")

    # Strip whitespace from column names
    df.columns = df.columns.str.strip()

    # Show label distribution
    if 'Label' in df.columns:
        print(f"\n      Label distribution:")
        print(df['Label'].value_counts().to_string())
    elif ' Label' in df.columns:
        print(f"\n      Label distribution:")
        print(df[' Label'].value_counts().to_string())

    return df


def prepare_features(df):
    print(f"\n[2/6] Preparing features...")

    # Find label column (handles spaces in column names)
    label_col = None
    for col in df.columns:
        if col.strip() == 'Label':
            label_col = col
            break

    if label_col is None:
        print("ERROR: Could not find 'Label' column")
        print(f"Available columns: {list(df.columns[:10])}")
        sys.exit(1)

    # Find feature columns (handles spaces)
    found_features = []
    for feature in FEATURE_COLS:
        for col in df.columns:
            if col.strip() == feature.strip():
                found_features.append(col)
                break

    print(f"      Found {len(found_features)} feature columns: {found_features}")

    if len(found_features) == 0:
        print("ERROR: No feature columns found. Check CSV column names.")
        sys.exit(1)

    # Filter to attack and benign rows only
    df_attack = df[df[label_col].str.strip() == ATTACK_LABEL].copy()
    df_benign = df[df[label_col].str.strip() == BENIGN_LABEL].copy()

    print(f"\n      Attack rows: {len(df_attack):,}")
    print(f"      Benign rows: {len(df_benign):,}")

    if len(df_benign) < 10:
        print("\n      WARNING: Very few benign rows found!")
        print("      The Kaggle 650MB file has only 392 benign rows.")
        print("      Model may have high false positive rate.")
        print("      Recommend using the 1.8GB University file instead.")

    # Balance the dataset
    n_attack = min(len(df_attack), MAX_SAMPLES_PER_CLASS)
    n_benign = min(len(df_benign), MAX_SAMPLES_PER_CLASS)

    # If benign is very small, keep all of it
    if len(df_benign) <= 500:
        n_benign = len(df_benign)
        n_attack = min(len(df_attack), n_benign * 20)  # max 20:1 ratio
        print(f"\n      Low benign count - using {n_attack:,} attack, {n_benign} benign")
    else:
        print(f"\n      Balanced sampling: {n_attack:,} attack, {n_benign:,} benign")

    df_attack_sample = df_attack.sample(n=n_attack, random_state=42)
    df_benign_sample = df_benign.sample(n=n_benign, random_state=42)

    df_combined = pd.concat([df_attack_sample, df_benign_sample])
    df_combined = df_combined.sample(frac=1, random_state=42).reset_index(drop=True)

    # Extract features and labels
    X = df_combined[found_features].values
    y = (df_combined[label_col].str.strip() == ATTACK_LABEL).astype(int).values

    # Handle NaN and infinite values
    X = np.nan_to_num(X, nan=0.0, posinf=1e10, neginf=0.0)

    print(f"\n      Final dataset: {len(X):,} samples")
    print(f"      Attack: {y.sum():,}, Benign: {(1-y).sum():,}")

    return X, y, found_features


# ============================================================
# TRAIN ALL 5 MODELS
# ============================================================

def train_models(X_train, X_test, y_train, y_test, scaler):
    print(f"\n[4/6] Training all 5 models (paper Table I)...")
    print(f"      Train size: {len(X_train):,}, Test size: {len(X_test):,}")

    # Scale features
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    models = {}
    results = {}

    # -----------------------------------------------------------
    # 1. Decision Tree (DT)
    # Paper: "DT's interpretability"
    # -----------------------------------------------------------
    print("\n      Training Decision Tree...")
    dt = DecisionTreeClassifier(
        max_depth=10,
        random_state=42,
        class_weight='balanced'
    )
    dt.fit(X_train_scaled, y_train)
    models['dt'] = dt
    results['DT'] = evaluate_model(dt, X_test_scaled, y_test)
    print(f"      DT  - P:{results['DT']['precision']:.3f} "
          f"R:{results['DT']['recall']:.3f} "
          f"F1:{results['DT']['f1']:.3f}")

    # -----------------------------------------------------------
    # 2. Random Forest (RF)
    # Paper: "RF's strong generalization"
    # -----------------------------------------------------------
    print("\n      Training Random Forest...")
    rf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    rf.fit(X_train_scaled, y_train)
    models['rf'] = rf
    results['RF'] = evaluate_model(rf, X_test_scaled, y_test)
    print(f"      RF  - P:{results['RF']['precision']:.3f} "
          f"R:{results['RF']['recall']:.3f} "
          f"F1:{results['RF']['f1']:.3f}")

    # -----------------------------------------------------------
    # 3. K-Nearest Neighbors (KNN)
    # Paper: "KN is slower"
    # -----------------------------------------------------------
    print("\n      Training KNN (this is the slow one)...")
    knn = KNeighborsClassifier(
        n_neighbors=5,
        n_jobs=-1
    )
    knn.fit(X_train_scaled, y_train)
    models['knn'] = knn
    results['KNN'] = evaluate_model(knn, X_test_scaled, y_test)
    print(f"      KNN - P:{results['KNN']['precision']:.3f} "
          f"R:{results['KNN']['recall']:.3f} "
          f"F1:{results['KNN']['f1']:.3f}")

    # -----------------------------------------------------------
    # 4. XGBoost
    # Paper: "XGBoost is resource-intensive"
    # -----------------------------------------------------------
    print("\n      Training XGBoost...")
    scale_pos_weight = (y_train == 0).sum() / max((y_train == 1).sum(), 1)
    xgb = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss',
        scale_pos_weight=scale_pos_weight,
        verbosity=0
    )
    xgb.fit(X_train_scaled, y_train)
    models['xgb'] = xgb
    results['XGBoost'] = evaluate_model(xgb, X_test_scaled, y_test)
    print(f"      XGB - P:{results['XGBoost']['precision']:.3f} "
          f"R:{results['XGBoost']['recall']:.3f} "
          f"F1:{results['XGBoost']['f1']:.3f}")

    # -----------------------------------------------------------
    # 5. Support Vector Machine (SVM)
    # Paper: "SVM" - lowest performer in paper
    # -----------------------------------------------------------
    print("\n      Training SVM (may take a few minutes)...")
    svm = SVC(
        kernel='rbf',
        C=1.0,
        gamma='scale',
        probability=True,
        class_weight='balanced',
        random_state=42
    )
    # SVM is slow on large datasets - limit training size
    max_svm = min(len(X_train_scaled), 20000)
    svm.fit(X_train_scaled[:max_svm], y_train[:max_svm])
    models['svm'] = svm
    results['SVM'] = evaluate_model(svm, X_test_scaled, y_test)
    print(f"      SVM - P:{results['SVM']['precision']:.3f} "
          f"R:{results['SVM']['recall']:.3f} "
          f"F1:{results['SVM']['f1']:.3f}")

    # -----------------------------------------------------------
    # Ensemble Vote
    # Paper Algorithm 3 line 5:
    # "result ← decision(isddos) {vote to 5 models}"
    # -----------------------------------------------------------
    print("\n      Evaluating Ensemble Vote...")
    results['Models Vote'] = evaluate_ensemble(models, X_test_scaled, y_test)
    print(f"      ENS - P:{results['Models Vote']['precision']:.3f} "
          f"R:{results['Models Vote']['recall']:.3f} "
          f"F1:{results['Models Vote']['f1']:.3f}")

    return models, results


def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    return {
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall':    recall_score(y_test, y_pred, zero_division=0),
        'f1':        f1_score(y_test, y_pred, zero_division=0),
        'accuracy':  accuracy_score(y_test, y_pred)
    }


def evaluate_ensemble(models, X_test, y_test):
    """
    Majority voting across all 5 models.
    Paper Algorithm 3: "vote to 5 models"
    """
    votes = np.zeros(len(X_test))
    for name, model in models.items():
        pred = model.predict(X_test)
        votes += pred

    # Majority vote: >2.5 means at least 3 of 5 voted attack
    y_pred = (votes > 2.5).astype(int)
    return {
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall':    recall_score(y_test, y_pred, zero_division=0),
        'f1':        f1_score(y_test, y_pred, zero_division=0),
        'accuracy':  accuracy_score(y_test, y_pred)
    }


# ============================================================
# SAVE MODELS
# ============================================================

def save_models(models, scaler, feature_names):
    print(f"\n[5/6] Saving models to {OUTPUT_DIR}/")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for name, model in models.items():
        path = os.path.join(OUTPUT_DIR, f'{name}_model.pkl')
        with open(path, 'wb') as f:
            pickle.dump(model, f)
        print(f"      Saved: {name}_model.pkl")

    scaler_path = os.path.join(OUTPUT_DIR, 'scaler.pkl')
    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"      Saved: scaler.pkl")

    # Save feature names so controller knows what to send
    features_path = os.path.join(OUTPUT_DIR, 'feature_names.pkl')
    with open(features_path, 'wb') as f:
        pickle.dump(feature_names, f)
    print(f"      Saved: feature_names.pkl")


# ============================================================
# PRINT RESULTS TABLE (matches paper Table I format)
# ============================================================

def print_results_table(results):
    print(f"\n[6/6] Results (compare with paper Table I):")
    print(f"\n{'='*55}")
    print(f"{'Model':<15} {'Precision':>10} {'Recall':>8} {'F1-score':>10}")
    print(f"{'='*55}")

    paper_results = {
        'SVM':         (0.983, 0.845, 0.901),
        'XGBoost':     (0.981, 0.929, 0.953),
        'KNN':         (0.985, 0.932, 0.958),
        'RF':          (0.991, 0.934, 0.960),
        'DT':          (0.990, 0.934, 0.960),
        'Models Vote': (0.992, 0.935, 0.961),
    }

    order = ['SVM', 'XGBoost', 'KNN', 'RF', 'DT', 'Models Vote']
    for model_name in order:
        if model_name in results:
            r = results[model_name]
            p_paper = paper_results[model_name]
            print(f"{model_name:<15} {r['precision']:>10.3f} "
                  f"{r['recall']:>8.3f} {r['f1']:>10.3f}  "
                  f"(paper: {p_paper[2]:.3f})")

    print(f"{'='*55}")
    print(f"\nModels saved to: {OUTPUT_DIR}/")
    print(f"\nNEXT STEP: Copy the ml/models/ folder to your WSL2 Ubuntu")
    print(f"           then run the controller: python3 controller/p4m3_controller.py")


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description='Train P4M3 ensemble ML models on CIC-DDoS2019 SYN flood data'
    )
    parser.add_argument(
        '--csv',
        required=True,
        help='Path to Syn.csv file (e.g., C:\\Users\\You\\Downloads\\Syn.csv)'
    )
    args = parser.parse_args()

    if not os.path.exists(args.csv):
        print(f"ERROR: File not found: {args.csv}")
        sys.exit(1)

    print("=" * 55)
    print("P4M3 Ensemble Model Training")
    print("Paper: Table I targets F1 > 0.96 for ensemble")
    print("=" * 55)

    # Load
    df = load_data(args.csv)

    # Prepare features
    X, y, feature_names = prepare_features(df)

    # Split 70/30 as mentioned in the other paper you referenced
    print(f"\n[3/6] Splitting data 70% train / 30% test...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    print(f"      Train: {len(X_train):,}, Test: {len(X_test):,}")

    # Fit scaler on training data only
    scaler = StandardScaler()
    scaler.fit(X_train)

    # Train
    models, results = train_models(X_train, X_test, y_train, y_test, scaler)

    # Save
    save_models(models, scaler, feature_names)

    # Print table
    print_results_table(results)


if __name__ == '__main__':
    main()
