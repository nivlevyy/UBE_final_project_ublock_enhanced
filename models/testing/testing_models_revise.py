import random
import hashlib
import joblib
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
import seaborn as sns
import warnings

warnings.filterwarnings('ignore')


def md5_hash_index(text, n_features=20):
    """Enhanced hash function with more features"""
    text = str(text) if text is not None else "nan"
    digest = hashlib.md5(text.encode()).digest()
    int_hash = int.from_bytes(digest[:4], "little", signed=False)
    index = int_hash % n_features
    sign = -1 if (int_hash & 1) else 1
    return index, sign


def custom_md5_hash_vector(parts, n_features=20):
    """Create hash vector from categorical parts"""
    vec = np.zeros(n_features, dtype=np.float32)
    for raw in parts:
        index, sign = md5_hash_index(raw, n_features)
        vec[index] += sign
    return vec


def prepare_all_features(df, exclude_direct_leakage=True):
    """
    Prepare ALL available features for maximum accuracy
    Only excludes direct VirusTotal reputation scores if specified
    """

    # Categorical columns to hash
    categorical_cols = []
    for col in ['Final Domain', 'SSL Issuer', 'Domain Registrar']:
        if col in df.columns:
            categorical_cols.append(col)

    # Features to potentially exclude (direct leakage)
    direct_leakage = ['VT Reputation', 'VT Malicious', 'VT Suspicious', 'VT Undetected', 'VT Harmless']

    # Columns to always exclude
    exclude_cols = ['URL', 'validity']

    if exclude_direct_leakage:
        exclude_cols.extend([col for col in direct_leakage if col in df.columns])
        print(f"Excluding direct leakage features: {[col for col in direct_leakage if col in df.columns]}")

    exclude_cols.extend(categorical_cols)

    # Get all numerical features
    numerical_cols = [col for col in df.columns if col not in exclude_cols]
    print(f"Using {len(numerical_cols)} numerical features")

    # Extract numerical features
    X_numeric = df[numerical_cols].copy()

    # Handle categorical features with hashing
    if categorical_cols:
        print(f"Hashing {len(categorical_cols)} categorical features")
        N_FEATURES = 20  # More hash features for better representation

        cat_data = df[categorical_cols].astype(str)
        hashed_mat = np.vstack(
            cat_data.apply(lambda r: custom_md5_hash_vector(r.values, n_features=N_FEATURES), axis=1).to_numpy()
        )

        hashed_df = pd.DataFrame(hashed_mat, columns=[f'hash_{i}' for i in range(N_FEATURES)])

        # Combine numerical and hashed features
        X = pd.concat([X_numeric.reset_index(drop=True), hashed_df.reset_index(drop=True)], axis=1)
    else:
        X = X_numeric

    # Fill any missing values
    X = X.fillna(0)

    print(f"Final feature matrix shape: {X.shape}")
    return X, numerical_cols


def get_best_models():
    """Return a set of high-performance models"""
    models = {
        'RandomForest': RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        ),
        'XGBoost': XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='logloss',
            n_jobs=-1
        ),
        'GradientBoosting': GradientBoostingClassifier(
            n_estimators=150,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42
        )
    }
    return models


def validate_model_performance(model, X, y, model_name):
    """
    Comprehensive validation to ensure the model performance is legitimate
    """
    print(f"\n🔍 Validating {model_name} Performance:")

    # 1. Cross-validation with multiple folds
    cv_scores = cross_val_score(model, X, y, cv=10, scoring='accuracy', n_jobs=-1)
    cv_f1_scores = cross_val_score(model, X, y, cv=10, scoring='f1', n_jobs=-1)

    print(f"📊 10-Fold CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    print(f"📊 10-Fold CV F1-Score: {cv_f1_scores.mean():.4f} (+/- {cv_f1_scores.std() * 2:.4f})")

    # 2. Multiple random splits
    accuracies = []
    f1_scores = []

    for i in range(10):
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=i, stratify=y
        )

        temp_model = type(model)(**model.get_params())
        temp_model.fit(X_train, y_train)
        y_pred = temp_model.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        f1 = classification_report(y_test, y_pred, output_dict=True, zero_division=0)['1']['f1-score']

        accuracies.append(acc)
        f1_scores.append(f1)

    print(f"📊 Multi-split Accuracy: {np.mean(accuracies):.4f} (+/- {np.std(accuracies) * 2:.4f})")
    print(f"📊 Multi-split F1-Score: {np.mean(f1_scores):.4f} (+/- {np.std(f1_scores) * 2:.4f})")

    # 3. Check for suspiciously perfect performance
    if np.mean(accuracies) > 0.99:
        print("⚠️  WARNING: Suspiciously high accuracy - possible data leakage!")
        return False
    elif np.mean(accuracies) > 0.95:
        print("✅ Excellent performance - likely legitimate!")
        return True
    elif np.mean(accuracies) > 0.90:
        print("✅ Very good performance!")
        return True
    else:
        print("📈 Good performance - room for improvement")
        return True


def train_best_model(df, exclude_leakage=True):
    """
    Train the best possible model with comprehensive validation
    """

    print("🚀 TRAINING HIGH-ACCURACY MODEL")
    print("=" * 50)

    # Prepare features
    X, feature_names = prepare_all_features(df, exclude_direct_leakage=exclude_leakage)
    y = df['validity'].map({'safe': 0, 'unsafe': 1})

    print(f"Dataset: {len(df)} samples, {X.shape[1]} features")
    print(f"Class distribution: {dict(y.value_counts())}")

    # Get models
    models = get_best_models()

    best_model = None
    best_score = 0
    best_name = ""
    results = {}

    # Test each model
    for name, model in models.items():
        print(f"\n{'=' * 30}")
        print(f"Training {name}")
        print(f"{'=' * 30}")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        # Train model
        model.fit(X_train, y_train)

        # Make predictions
        y_pred = model.predict(X_test)
        y_pred_proba = model.predict_proba(X_test)

        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)

        print(f"Test Accuracy: {accuracy:.4f}")
        print(f"Test F1-Score: {report['1']['f1-score']:.4f}")
        print(f"Test Precision: {report['1']['precision']:.4f}")
        print(f"Test Recall: {report['1']['recall']:.4f}")

        # Validate performance
        is_legitimate = validate_model_performance(model, X, y, name)

        # Store results
        results[name] = {
            'model': model,
            'accuracy': accuracy,
            'f1_score': report['1']['f1-score'],
            'precision': report['1']['precision'],
            'recall': report['1']['recall'],
            'is_legitimate': is_legitimate,
            'y_test': y_test,
            'y_pred': y_pred,
            'y_pred_proba': y_pred_proba
        }

        # Track best model
        if report['1']['f1-score'] > best_score and is_legitimate:
            best_score = report['1']['f1-score']
            best_model = model
            best_name = name

    if best_model is None:
        print("\n❌ No legitimate high-performance model found!")
        return None, None

    print(f"\n🏆 BEST MODEL: {best_name}")
    print(f"🎯 F1-Score: {best_score:.4f}")

    # Final evaluation of best model
    print(f"\n{'=' * 50}")
    print("FINAL MODEL EVALUATION")
    print(f"{'=' * 50}")

    best_results = results[best_name]

    # Confusion Matrix
    cm = confusion_matrix(best_results['y_test'], best_results['y_pred'])
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Safe', 'Malicious'],
                yticklabels=['Safe', 'Malicious'])
    plt.title(f'Confusion Matrix - {best_name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.show()

    # Feature Importance
    if hasattr(best_model, 'feature_importances_'):
        importances = best_model.feature_importances_
        feature_importance_df = pd.DataFrame({
            'Feature': X.columns,
            'Importance': importances
        }).sort_values(by='Importance', ascending=False).head(20)

        plt.figure(figsize=(12, 8))
        plt.barh(range(len(feature_importance_df)), feature_importance_df['Importance'])
        plt.yticks(range(len(feature_importance_df)), feature_importance_df['Feature'])
        plt.xlabel('Importance')
        plt.title(f'Top 20 Feature Importances - {best_name}')
        plt.gca().invert_yaxis()
        plt.tight_layout()
        plt.show()

        print("\nTop 10 Most Important Features:")
        for i, (feature, importance) in enumerate(feature_importance_df.head(10).values):
            print(f"{i + 1:2d}. {feature:<30} {importance:.4f}")

    return best_model, best_name


def test_with_and_without_vt(df):
    """
    Test model performance with and without VirusTotal features
    to demonstrate the difference
    """

    print("\n" + "=" * 60)
    print("COMPARING WITH AND WITHOUT VIRUSTOTAL FEATURES")
    print("=" * 60)

    # Test WITHOUT VirusTotal features
    print("\n🧪 Testing WITHOUT VirusTotal features (Clean):")
    model_clean, name_clean = train_best_model(df, exclude_leakage=True)

    # Test WITH VirusTotal features
    print("\n🧪 Testing WITH VirusTotal features (Potential Leakage):")
    model_leakage, name_leakage = train_best_model(df, exclude_leakage=False)

    return model_clean, model_leakage

#
# if __name__ == "__main__":
#     from tkinter import Tk, filedialog
#
#     # File selection
#     root = Tk()
#     root.withdraw()
#     input_file = filedialog.askopenfilename(
#         title="Select input CSV file",
#         filetypes=[("CSV files", "*.csv")]
#     )
#
#     if not input_file:
#         print("No input file selected.")
#         exit(1)
#
#     # Load data
#     print("Loading dataset...")
#     df = pd.read_csv(input_file)
#
#     print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns")
#
#     # Train the best model (excluding direct leakage features)
#     best_model, best_name = train_best_model(df, exclude_leakage=True)
#
#     if best_model:
#         # Save the model
#         model_filename = f"best_model_{best_name.lower()}.pkl"
#         joblib.dump(best_model, model_filename)
#         print(f"\n💾 Model saved as: {model_filename}")
#
#         print("\n✅ HIGH-ACCURACY MODEL TRAINING COMPLETED!")
#         print(f"🎯 Best Model: {best_name}")
#         print("🔍 Performance has been thoroughly validated")
#         print("📊 Check the confusion matrix and feature importance plots")
#
#     # Optional: Compare with and without VT features
#     response = input("\nDo you want to compare performance with/without VirusTotal features? (y/n): ")
#     if response.lower() == 'y':
#         test_with_and_without_vt(df)
import pandas as pd
import numpy as np
import hashlib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from tkinter import Tk, filedialog

# === פונקציות hash בדיוק כמו ששלחת ===
def md5_hash_index(text, n_features=10):
    text = str(text) if text is not None else "nan"
    digest = hashlib.md5(text.encode()).digest()
    int_hash = int.from_bytes(digest[:4], "little", signed=False)
    index = int_hash % n_features
    sign = -1 if (int_hash & 1) else 1
    return index, sign

def custom_md5_hash_vector(parts, n_features=10):
    vec = np.zeros(n_features, dtype=np.float32)
    for raw in parts:
        index, sign = md5_hash_index(raw, n_features)
        vec[index] += sign
    return vec

# === הרצת מודל על כל הדאטה ===
def run_model(df: pd.DataFrame, train_size: float = 0.8):
    N_FEATURES = 10

    # שמות מדויקים של העמודות הקטגוריות
    categorical_cols = ['Final Domain', 'Domain Registrar']
    categorical_cols = [col for col in categorical_cols if col in df.columns]

    if len(categorical_cols) < 3:
        print("⚠️ Warning: Not all categorical columns found in dataset.")
        print("Found:", categorical_cols)

    # hashing
    hashed_mat = np.vstack(
        df[categorical_cols]
        .astype(str)
        .apply(lambda r: custom_md5_hash_vector(r.values, n_features=N_FEATURES), axis=1)
        .to_numpy()
    )
    hashed_df = pd.DataFrame(hashed_mat, columns=[f'h{i}' for i in range(N_FEATURES)])

    # פיצ'רים נומריים בלבד
    drop_cols = [col for col in ['URL', 'validity'] + categorical_cols if col in df.columns]
    X_numeric = df.drop(columns=drop_cols)

    X = pd.concat([X_numeric.reset_index(drop=True), hashed_df.reset_index(drop=True)], axis=1)
    y = df['validity'].map({'safe': 0, 'unsafe': 1})

    x_train, x_test, y_train, y_test = train_test_split(X, y, train_size=train_size, stratify=y, random_state=42)
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(x_train, y_train)

    print("\n📊 Model Evaluation:")
    print(classification_report(y_test, model.predict(x_test)))

    return model, X.columns


# === MAIN ===
if __name__ == "__main__":
    # שלב 1: בחר קובץ אימון
    root = Tk()
    root.withdraw()
    print("📥 Select training dataset:")
    train_file = filedialog.askopenfilename(filetypes=[("CSV files", "*.csv")])
    if not train_file:
        print("❌ No training file selected.")
        exit()

    df_train = pd.read_csv(train_file)
    model, feature_names = run_model(df_train)

    # שלב 2: בחר קובץ עם שורה לבדיקה
    model, feature_names = run_model(df_train)

    # === שלב 2: שורת בדיקה ידנית (list)
    test_row = [
        67, 7, 42, 0, 0, 3, 2, 6, 6, 1, 0, 1, 1,
        0, 1, 90, 350,
        17, 18, 0.55,
        20, 22, 0.91,
        200, 225, 0.888,
        420,
        440,
        0.73,
        13, 10, 9, 1,
        "alert-reset-now-login.com", "Self-Signed Authority", "No Name Registrar"
    ]

    # === שלב 3: Hash לפיצ’רים הקטגוריים
    cat_values = test_row[-3:]  # שלוש הקטגוריות
    hashed_vec = custom_md5_hash_vector(cat_values, n_features=10)

    # === שלב 4: בניית השורה הסופית
    numeric_values = test_row[:-3]
    full_row = np.concatenate([numeric_values, hashed_vec])
    test_df = pd.DataFrame([full_row], columns=feature_names)

    # === שלב 5: ניבוי
    pred = model.predict(test_df)[0]
    proba = model.predict_proba(test_df)[0]

    # === תוצאה
    print("\n🔍 Prediction on manual test row:")
    print("🧪 Prediction:", "Phishing" if pred == 1 else "Safe")
    print(f"📊 Confidence: phishing={proba[1]:.4f}, safe={proba[0]:.4f}")
