from tkinter import Tk, filedialog

import pandas as pd
import lightgbm as lgb
import sys, m2cgen as m2c
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, roc_auc_score, f1_score
from pathlib import Path

# ─────────── USER CONFIGURATION ───────────
FEATURE_COLS = [
            'URL Length', 'Number of Subdomains', 'Length of Hostname',
            'Is IP Address', 'Is URL Shortener', 'Number of Hyphens',
            'Number of @ signs', 'Number of Query Parameters', 'Number of Directories',
            'Has Protocol', 'Is Mail', 'Has Suspicious Chars', 'Has Double Slash',
            'Has SSL', 'Valid SSL', 'Domain Age', 'Domain Expiration',
            'VT Reputation', 'VT Malicious', 'VT Suspicious', 'VT Undetected',
            'VT Harmless', 'has_icon', 'favicon_diff_domain', 'favicon_invalid_ext',
            'anchor_tags_present', 'anchor_empty_href', 'anchor_diff_domain',
            'anchor_diff_ratio', 'meta_external', 'meta_sus_words', 'external_meta_ratio',
            'script_external', 'script_sus_words', 'external_script_ratio',
            'total_links', 'external_link_count', 'ratio_extern_link',
            'total_external', 'total_resources', 'external_resources',
            'external_request_ratio', 'sfh_total_forms', 'sfh_blank_action',
            'sfh_diff_domain', 'sfh_password_inputs', 'sfh_suspicious_inputs',
            'iframe_src_count', 'iframe_src_hidden', 'iframe_src_size',
            'iframe_src_diff_domain', 'iframe_src_no_sandbox', 'iframe_external_src_ratio',
            'iframe_srcdoc_count', 'iframe_srcdoc_hidden', 'iframe_srcdoc_scripts',
            'iframe_srcdoc_sus_words', 'total_iframes', 'inline_scripts',
            'high_risk_patterns', 'medium_risk_patterns', 'low_risk_patterns',
            'sus_js_diff_domain', 'sus_js_behave_ratio', 'risk_patterns_ratio',
            'nlp_suspicious_words', 'onmouseover_scripts', 'onmouseover_tags',
            'right_click_scripts', 'right_click_tags', 'Different Domains'
        ]
LABEL_COL = 'validity'

# ───────────────────────────────────────────
def main():
    root = Tk()
    root.withdraw()
    input_file = filedialog.askopenfilename(title="Select input CSV file", filetypes=[("CSV files", "*.csv")])
    selected_dir = filedialog.askdirectory(title="Select output directory for model artifacts")
    root.destroy()

    if not input_file or not selected_dir:
        print("No input file selected.")
        exit(1)

    OUTPUT_DIR = Path(selected_dir) if selected_dir else Path("./export")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. Load data
    df = pd.read_csv(input_file)
    X = df[FEATURE_COLS]

    label_map = {"safe": 0, "unsafe": 1}
    y = df[LABEL_COL].map(label_map).astype(int).values

    # 2. Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # 3. Fit LightGBM
    print("Training LightGBM …")
    clf = lgb.LGBMClassifier(
        num_leaves=48,
        n_estimators=600,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # 4. Metrics
    proba = clf.predict_proba(X_test)[:, 1]
    preds = (proba >= 0.5).astype(int)
    print("\n=== Hold‑out metrics ===")
    print(f"Accuracy : {accuracy_score(y_test, preds):.3f}")
    print(f"F1‑score : {f1_score(y_test, preds):.3f}")
    print(f"ROC‑AUC  : {roc_auc_score(y_test, proba):.3f}")

    # 5. Export JS scorer for the extension
    sys.setrecursionlimit(20000)
    js_code = m2c.export_to_javascript(clf, indent=0)
    (OUTPUT_DIR / "model.js").write_text(js_code, encoding="utf‑8")
    print("✓ model.js written (ready for import { score } …)")

    # 6. OPTIONAL: LightGBM text dump and full‑dataset predictions
    clf.booster_.save_model(OUTPUT_DIR / "model.txt")
    print("✓ model.txt written (LightGBM dump – optional)")

    df["prediction_proba"] = clf.predict_proba(X)[:, 1]
    df[[*FEATURE_COLS, LABEL_COL, "prediction_proba"]].to_csv(
        OUTPUT_DIR / "predictions.csv", index=False
    )
    print("✓ predictions.csv written (all rows with probabilities)")

    print("Done.")

if __name__ == "__main__":
    main()