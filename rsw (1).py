# ==========================================
# 📌 RANSOMWARE DETECTION - RESEARCH PIPELINE
# ==========================================

import os, warnings, joblib, random
import numpy as np
import pandas as pd

# Fix matplotlib backend
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, confusion_matrix, classification_report
)
from sklearn.ensemble import RandomForestClassifier, StackingClassifier
from sklearn.feature_selection import SelectFromModel

from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from catboost import CatBoostClassifier

from imblearn.over_sampling import SMOTE

warnings.filterwarnings("ignore")

# ==========================================
# 🔒 REPRODUCIBILITY
# ==========================================
SEED = 42
np.random.seed(SEED)
random.seed(SEED)

# ==========================================
# 📁 OUTPUT STRUCTURE
# ==========================================
BASE_DIR = "research_results"
MODEL_DIR = os.path.join(BASE_DIR, "models")
PLOT_DIR = os.path.join(BASE_DIR, "plots")
TABLE_DIR = os.path.join(BASE_DIR, "tables")

for d in [BASE_DIR, MODEL_DIR, PLOT_DIR, TABLE_DIR]:
    os.makedirs(d, exist_ok=True)

# ==========================================
# 📊 LOAD & CLEAN DATA
# ==========================================
def load_data(path):
    df = pd.read_csv(path)
    df = df.drop_duplicates()
    df = df.replace(["?", "NA", "", "null"], np.nan)
    df = df.fillna(0)
    return df

# ==========================================
# 🧠 FEATURE ENGINEERING
# ==========================================
def feature_engineering(df):
    df["has_crypto"] = (df["BitcoinAddresses"] > 0).astype(int)
    df["size_ratio"] = df["ResourceSize"] / (df["SizeOfStackReserve"] + 1)
    df["section_ratio"] = df["NumberOfSections"] / (df["SizeOfStackReserve"] + 1)
    df["high_iat"] = (df["IatVRA"] > 100000).astype(int)
    df["entropy_like"] = df["ResourceSize"] * df["ExportSize"]

    df = df.drop(columns=[c for c in ["FileName", "md5Hash"] if c in df.columns])
    return df

# ==========================================
# 📦 DATA PREPARATION
# ==========================================
def prepare_data(df):
    X = df.drop("Benign", axis=1)
    y = df["Benign"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=SEED
    )

    smote = SMOTE(random_state=SEED)
    X_train, y_train = smote.fit_resample(X_train, y_train)

    selector = SelectFromModel(RandomForestClassifier(n_estimators=200, random_state=SEED))
    X_train = selector.fit_transform(X_train, y_train)
    X_test = selector.transform(X_test)

    return X_train, X_test, y_train, y_test, selector

# ==========================================
# 🤖 MODELS
# ==========================================
def get_models():
    models = {
        "RandomForest": RandomForestClassifier(n_estimators=400, class_weight='balanced', random_state=SEED),

        "XGBoost": XGBClassifier(
            n_estimators=700, max_depth=7, learning_rate=0.03,
            subsample=0.8, colsample_bytree=0.8, eval_metric='logloss'
        ),

        "LightGBM": LGBMClassifier(
            n_estimators=1000, learning_rate=0.03,
            num_leaves=64, subsample=0.8, colsample_bytree=0.8,
            random_state=SEED
        ),

        "CatBoost": CatBoostClassifier(
            iterations=1000, depth=6, learning_rate=0.03, verbose=0
        )
    }

    stack = StackingClassifier(
        estimators=[(k.lower(), v) for k, v in models.items()],
        final_estimator=XGBClassifier(n_estimators=200),
        cv=5,
        n_jobs=-1
    )

    models["Stacking"] = stack
    return models

# ==========================================
# 📊 EVALUATION FUNCTION
# ==========================================
def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    
    # Cross-validation
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    cv_score = cross_val_score(model, X_train, y_train, cv=cv, scoring="f1").mean()

    model.fit(X_train, y_train)

    y_prob = model.predict_proba(X_test)[:, 1]
    y_pred = (y_prob > 0.4).astype(int)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc = roc_auc_score(y_test, y_prob)

    # Save confusion matrix
    cm = confusion_matrix(y_test, y_pred)

    plt.figure()
    plt.imshow(cm)
    plt.title(f"{name} Confusion Matrix")
    plt.colorbar()
    plt.savefig(os.path.join(PLOT_DIR, f"{name}_cm.png"))
    plt.close()

    # Save classification report
    report = classification_report(y_test, y_pred)
    with open(os.path.join(TABLE_DIR, f"{name}_report.txt"), "w") as f:
        f.write(report)

    # Save model
    joblib.dump(model, os.path.join(MODEL_DIR, f"{name}.pkl"))

    return {
        "Model": name,
        "Accuracy": acc,
        "Precision": prec,
        "Recall": rec,
        "F1 Score": f1,
        "ROC-AUC": roc,
        "CV Score": cv_score
    }

# ==========================================
# 🚀 MAIN PIPELINE
# ==========================================
def main():
    print("🚀 Starting Research Pipeline...")

    df = load_data("data_file (3).csv")
    df = feature_engineering(df)

    X_train, X_test, y_train, y_test, selector = prepare_data(df)
    models = get_models()

    results = []

    for name, model in models.items():
        print(f"\n🔹 Training {name}...")
        res = evaluate_model(name, model, X_train, X_test, y_train, y_test)
        print(f"{name} -> Acc:{res['Accuracy']:.4f} F1:{res['F1 Score']:.4f}")
        results.append(res)

    # Save comparison table
    df_results = pd.DataFrame(results).sort_values(by="F1 Score", ascending=False)
    df_results.to_csv(os.path.join(TABLE_DIR, "model_comparison.csv"), index=False)

    # Plot comparison
    df_results.set_index("Model")[["Accuracy", "F1 Score"]].plot(kind="bar")
    plt.title("Model Comparison")
    plt.tight_layout()
    plt.savefig(os.path.join(PLOT_DIR, "comparison_plot.png"))
    plt.close()

    print("\n✅ Research pipeline completed successfully!")

# ==========================================
# ENTRY POINT
# ==========================================
if __name__ == "__main__":
    main()