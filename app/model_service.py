"""Loads the trained models once and scores a feature dict. No training happens here."""
import csv, json, logging, pathlib, threading, warnings
import numpy as np
import joblib

from .pe_features import ALL_FEATURES

log = logging.getLogger("detector.models")
ROOT = pathlib.Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models"

# Display order; Stacking is the meta-ensemble of the four others.
MODEL_NAMES = ["RandomForest", "XGBoost", "LightGBM", "CatBoost", "Stacking"]
LABELS = {1: "Benign", 0: "Malicious"}     # target column in training was named "Benign"


class ModelService:
    def __init__(self):
        self.models, self.errors = {}, {}
        self.lock = threading.Lock()
        cfg = json.loads((MODEL_DIR / "feature_selection.json").read_text())
        self.mapping_status = cfg["status"]                       # "inferred" | "verified"
        self.mapping_note = cfg.get("how_determined", "")
        self.features = cfg["selected_features"]
        self.threshold = float(cfg.get("decision_threshold_benign", 0.4))
        unknown = [f for f in self.features if f not in ALL_FEATURES]
        if unknown:
            raise RuntimeError(f"feature_selection.json lists unknown features: {unknown}")
        self.metrics = self._load_training_metrics()

    @staticmethod
    def _load_training_metrics():
        p = ROOT / "reference" / "tables" / "model_comparison.csv"
        if not p.exists():
            return {}
        with p.open(newline="") as fh:
            return {r["Model"]: {k: float(v) for k, v in r.items() if k != "Model"} for r in csv.DictReader(fh)}

    def load(self):
        for name in MODEL_NAMES:
            path = MODEL_DIR / f"{name}.pkl"
            try:
                # NOTE: pickle can execute code on load. Only load model files you trust.
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    m = joblib.load(path)
                n_in = getattr(m, "n_features_in_", None) or len(getattr(m, "feature_names_", []) or [])
                if n_in != len(self.features):
                    raise ValueError(f"expects {n_in} features but feature_selection.json has {len(self.features)}")
                self.models[name] = m
                log.info("loaded %s (%d features)", name, n_in)
            except Exception as exc:                                   # keep serving the rest
                self.errors[name] = f"{type(exc).__name__}: {exc}"
                log.error("failed to load %s: %s", name, exc)
        if not self.models:
            raise RuntimeError("No models could be loaded")

    def predict(self, feats: dict) -> dict:
        x = np.array([[float(feats[f]) for f in self.features]], dtype=np.float64)
        results = []
        for name in MODEL_NAMES:
            m = self.models.get(name)
            if m is None:
                results.append({"model": name, "available": False, "error": self.errors.get(name, "not loaded")})
                continue
            with self.lock, warnings.catch_warnings():
                warnings.simplefilter("ignore")
                p_benign = float(m.predict_proba(x)[0, 1])
            is_benign = p_benign > self.threshold                    # same rule as training evaluation
            results.append({
                "model": name, "available": True,
                "label": LABELS[int(is_benign)],
                "p_malicious": round(1 - p_benign, 6),
                "p_benign": round(p_benign, 6),
                "training_metrics": self.metrics.get(name),
            })
        ok = [r for r in results if r["available"]]
        mal_votes = sum(r["label"] == "Malicious" for r in ok)
        verdict = "Malicious" if mal_votes * 2 > len(ok) else "Benign"   # strict majority; tie -> Benign
        mean_pm = float(np.mean([r["p_malicious"] for r in ok]))
        return {
            "verdict": verdict,
            "votes": {"malicious": mal_votes, "benign": len(ok) - mal_votes, "total": len(ok)},
            "mean_p_malicious": round(mean_pm, 6),
            "models": results,
            "model_features_used": {f: feats[f] for f in self.features},
        }
