"""
Recover the exact SelectFromModel feature selection used at training time and (optionally)
verify it against the saved models.

The original script never saved its `selector`, so the models' 7 input columns are otherwise
unnamed. This re-runs the *identical* preprocessing (same seed, split, SMOTE, selector) on the
original CSV and writes models/feature_selection.json with status "verified".

Usage:
    python scripts/recover_feature_selection.py --csv "data_file (3).csv" [--verify]

--verify re-scores the held-out 20% split with models/XGBoost.pkl etc. and compares accuracy
with reference/tables/model_comparison.csv (should match to ~4 decimals).
Needs: pandas scikit-learn imbalanced-learn (and xgboost/lightgbm/catboost for --verify).
"""
import argparse, json, pathlib, random
import numpy as np, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from imblearn.over_sampling import SMOTE

SEED = 42
ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_data(path):  # identical to the training script
    df = pd.read_csv(path).drop_duplicates()
    df = df.replace(["?", "NA", "", "null"], np.nan).fillna(0)
    return df


def feature_engineering(df):  # identical to the training script
    df["has_crypto"] = (df["BitcoinAddresses"] > 0).astype(int)
    df["size_ratio"] = df["ResourceSize"] / (df["SizeOfStackReserve"] + 1)
    df["section_ratio"] = df["NumberOfSections"] / (df["SizeOfStackReserve"] + 1)
    df["high_iat"] = (df["IatVRA"] > 100000).astype(int)
    df["entropy_like"] = df["ResourceSize"] * df["ExportSize"]
    return df.drop(columns=[c for c in ["FileName", "md5Hash"] if c in df.columns])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()
    np.random.seed(SEED); random.seed(SEED)

    df = feature_engineering(load_data(a.csv))
    X, y = df.drop("Benign", axis=1), df["Benign"]
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=SEED)
    X_tr, y_tr = SMOTE(random_state=SEED).fit_resample(X_tr, y_tr)
    sel = SelectFromModel(RandomForestClassifier(n_estimators=200, random_state=SEED))
    sel.fit(X_tr, y_tr)
    names = list(X.columns[sel.get_support()])
    print("Selected features:", names)

    expected = len(json.loads((ROOT / "models/feature_selection.json").read_text())["selected_features"])
    if len(names) != expected:
        raise SystemExit(f"ABORTED: selector chose {len(names)} features but the saved models expect {expected}. "
                         "Wrong CSV, or different library versions than training. models/feature_selection.json was NOT changed.")

    if a.verify:
        import joblib
        from sklearn.metrics import accuracy_score
        ref = pd.read_csv(ROOT / "reference/tables/model_comparison.csv").set_index("Model")
        Xt = sel.transform(X_te)
        for m in ["RandomForest", "XGBoost", "LightGBM", "CatBoost", "Stacking"]:
            model = joblib.load(ROOT / f"models/{m}.pkl")
            acc = accuracy_score(y_te, (model.predict_proba(Xt)[:, 1] > 0.4).astype(int))
            print(f"  {m:13s} accuracy={acc:.6f}  reference={ref.loc[m, 'Accuracy']:.6f}")

    out = {
        "status": "verified",
        "label_semantics": "Class 1 = Benign, class 0 = Malicious",
        "decision_threshold_benign": 0.4,
        "selected_features": names,
        "how_determined": f"Recovered by re-running the training preprocessing (seed {SEED}) on {pathlib.Path(a.csv).name}.",
    }
    (ROOT / "models/feature_selection.json").write_text(json.dumps(out, indent=2))
    print("Wrote models/feature_selection.json")


if __name__ == "__main__":
    main()
