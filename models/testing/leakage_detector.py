import pandas as pd
import numpy as np
from sklearn.metrics import mutual_info_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import seaborn as sns
import matplotlib.pyplot as plt
from scipy.stats import chi2_contingency, pearsonr
import warnings

warnings.filterwarnings('ignore')


class EnhancedLeakageDetector:
    def __init__(self, df, target_column='validity'):
        self.df = df.copy()
        self.target_column = target_column
        self.target = df[target_column].map({'safe': 0, 'unsafe': 1}) if df[target_column].dtype == 'object' else df[
            target_column]
        self.leakage_report = {}

    def detect_virustotal_leakage(self):
        """Detect ALL VirusTotal-related features - they are all leakage"""
        print("🔍 Detecting VirusTotal Features (ALL are leakage)...")
        print("=" * 60)

        vt_patterns = ['vt', 'virus', 'total', 'reputation', 'malicious', 'suspicious', 'undetected', 'harmless']
        vt_features = []

        for col in self.df.columns:
            col_lower = col.lower().replace(' ', '_').replace('-', '_')
            for pattern in vt_patterns:
                if pattern in col_lower:
                    vt_features.append(col)
                    print(f"🚨 LEAKAGE: {col} - VirusTotal derived feature")
                    break

        self.leakage_report['virustotal_features'] = vt_features
        return vt_features

    def detect_analysis_derived_features(self):
        """Detect features that are derived from content analysis that would happen AFTER classification"""
        print("\n🔍 Detecting Analysis-Derived Features...")
        print("=" * 60)

        analysis_patterns = [
            'risk_pattern', 'sus_js', 'suspicious', 'malicious', 'threat', 'score', 'rating',
            'verdict', 'result', 'classification', 'analysis', 'detection', 'behavior',
            'behave', 'high_risk', 'medium_risk', 'low_risk'
        ]

        analysis_features = []

        for col in self.df.columns:
            col_lower = col.lower().replace(' ', '_').replace('-', '_')
            for pattern in analysis_patterns:
                if pattern in col_lower:
                    analysis_features.append(col)
                    print(f"🚨 LEAKAGE: {col} - Analysis-derived feature")
                    break

        self.leakage_report['analysis_derived'] = analysis_features
        return analysis_features

    def detect_perfect_predictors(self, threshold=0.95):
        """Detect features that can predict the target with >95% accuracy by themselves"""
        print("\n🔍 Detecting Perfect Predictors...")
        print("=" * 60)

        perfect_predictors = []

        for col in self.df.columns:
            if col == self.target_column:
                continue

            try:
                # For categorical features
                if self.df[col].dtype in ['object', 'category']:
                    if len(self.df[col].unique()) < 100:
                        # Calculate predictive power
                        class_dist = self.df.groupby(col)[self.target_column].value_counts(normalize=True).unstack(
                            fill_value=0)
                        if len(class_dist) > 1:
                            max_prediction_accuracy = class_dist.max(axis=1).mean()
                            if max_prediction_accuracy > threshold:
                                perfect_predictors.append((col, max_prediction_accuracy))
                                print(f"🚨 LEAKAGE: {col} - Predicts with {max_prediction_accuracy:.4f} accuracy")

                # For numerical features - check if any threshold gives perfect separation
                else:
                    safe_values = self.df[self.df[self.target_column] == 'safe'][col].dropna()
                    unsafe_values = self.df[self.df[self.target_column] == 'unsafe'][col].dropna()

                    if len(safe_values) > 0 and len(unsafe_values) > 0:
                        # Try various thresholds
                        all_values = sorted(set(safe_values.tolist() + unsafe_values.tolist()))

                        for threshold_val in all_values[::max(1, len(all_values) // 20)]:  # Sample thresholds
                            safe_above = (safe_values > threshold_val).sum()
                            safe_below = len(safe_values) - safe_above
                            unsafe_above = (unsafe_values > threshold_val).sum()
                            unsafe_below = len(unsafe_values) - unsafe_above

                            # Check accuracy for threshold
                            accuracy1 = (safe_above + unsafe_below) / (len(safe_values) + len(unsafe_values))
                            accuracy2 = (safe_below + unsafe_above) / (len(safe_values) + len(unsafe_values))

                            max_acc = max(accuracy1, accuracy2)
                            if max_acc > threshold:
                                perfect_predictors.append((col, max_acc))
                                print(f"🚨 LEAKAGE: {col} - Threshold {threshold_val} gives {max_acc:.4f} accuracy")
                                break

            except Exception as e:
                continue

        self.leakage_report['perfect_predictors'] = perfect_predictors
        return perfect_predictors

    def detect_impossible_features(self):
        """Detect features that would be impossible to know at prediction time"""
        print("\n🔍 Detecting Impossible-to-Know Features...")
        print("=" * 60)

        impossible_patterns = [
            'reputation', 'scan', 'detection', 'verdict', 'analysis', 'result',
            'classification', 'threat', 'malware', 'phishing', 'spam'
        ]

        impossible_features = []

        for col in self.df.columns:
            col_lower = col.lower().replace(' ', '_').replace('-', '_')
            for pattern in impossible_patterns:
                if pattern in col_lower:
                    impossible_features.append(col)
                    print(f"🚨 LEAKAGE: {col} - Impossible to know before classification")
                    break

        self.leakage_report['impossible_features'] = impossible_features
        return impossible_features

    def analyze_feature_by_name_and_values(self):
        """Analyze features by name patterns and value distributions"""
        print("\n🔍 Deep Analysis of Feature Names and Values...")
        print("=" * 60)

        suspicious_by_name = []

        # Patterns that suggest the feature is derived from knowing the answer
        highly_suspicious_patterns = [
            'malicious', 'suspicious', 'threat', 'dangerous', 'harmful',
            'safe', 'secure', 'trusted', 'legitimate', 'benign'
        ]

        moderately_suspicious_patterns = [
            'reputation', 'score', 'rating', 'rank', 'classification',
            'category', 'label', 'verdict', 'analysis', 'detection'
        ]

        for col in self.df.columns:
            if col == self.target_column:
                continue

            col_lower = col.lower().replace(' ', '_').replace('-', '_')

            # Check for highly suspicious patterns
            for pattern in highly_suspicious_patterns:
                if pattern in col_lower:
                    suspicious_by_name.append((col, f"Contains '{pattern}' - directly related to classification"))
                    print(f"🚨 HIGH RISK: {col} - Contains '{pattern}'")
                    break
            else:
                # Check for moderately suspicious patterns
                for pattern in moderately_suspicious_patterns:
                    if pattern in col_lower:
                        suspicious_by_name.append((col, f"Contains '{pattern}' - likely derived from classification"))
                        print(f"⚠️  MEDIUM RISK: {col} - Contains '{pattern}'")
                        break

        self.leakage_report['suspicious_by_name'] = suspicious_by_name
        return suspicious_by_name

    def create_truly_clean_dataset(self):
        """Create a dataset with ALL potential leakage removed"""
        print("\n" + "=" * 80)
        print("🔍 COMPREHENSIVE LEAKAGE REMOVAL")
        print("=" * 80)

        # Collect all suspicious features
        all_leakage = set()

        # Run all detection methods
        vt_features = self.detect_virustotal_leakage()
        analysis_features = self.detect_analysis_derived_features()
        perfect_predictors = self.detect_perfect_predictors()
        impossible_features = self.detect_impossible_features()
        suspicious_names = self.analyze_feature_by_name_and_values()

        # Add all to the leakage set
        all_leakage.update(vt_features)
        all_leakage.update(analysis_features)
        all_leakage.update([feat for feat, _ in perfect_predictors])
        all_leakage.update(impossible_features)
        all_leakage.update([feat for feat, _ in suspicious_names])

        # Manual removal of obviously problematic features
        manual_leakage = [
            'VT Undetected',  # This is clearly from VirusTotal
            'high_risk_patterns',  # This is analysis result
            'medium_risk_patterns',  # This is analysis result
            'low_risk_patterns',  # This is analysis result
            'risk_patterns_ratio',  # This is analysis result
            'sus_js_behave_ratio',  # This suggests suspicious behavior (classification result)
            'sus_js_diff_domain'  # This suggests suspicious behavior (classification result)
        ]

        for feat in manual_leakage:
            if feat in self.df.columns:
                all_leakage.add(feat)
                print(f"🚨 MANUAL REMOVAL: {feat}")

        # Create truly clean feature list
        clean_features = [col for col in self.df.columns
                          if col not in all_leakage and col != self.target_column]

        print(f"\n📊 LEAKAGE REMOVAL SUMMARY:")
        print(f"🚨 Total leakage features removed: {len(all_leakage)}")
        print(f"✅ Clean features remaining: {len(clean_features)}")

        print(f"\n🚨 REMOVED FEATURES:")
        print("-" * 50)
        for i, feat in enumerate(sorted(all_leakage), 1):
            print(f"{i:2d}. {feat}")

        print(f"\n✅ CLEAN FEATURES (should give realistic accuracy):")
        print("-" * 50)
        for i, feat in enumerate(clean_features, 1):
            print(f"{i:2d}. {feat}")

        # Create clean dataset
        clean_df = self.df[clean_features + [self.target_column]].copy()

        return clean_df, list(all_leakage), clean_features


def analyze_and_clean_dataset(csv_file):
    """Main function to analyze and clean dataset"""
    df = pd.read_csv(csv_file)
    print(f"Original dataset: {df.shape[0]} rows, {df.shape[1]} columns")

    detector = EnhancedLeakageDetector(df)
    clean_df, leakage_features, clean_features = detector.create_truly_clean_dataset()

    print(f"\n🎯 FINAL RECOMMENDATION:")
    print(f"Use only the {len(clean_features)} clean features for training.")
    print(f"Expected accuracy should be 75-90% (realistic for URL classification)")
    print(f"If you still get >95% accuracy, there may be additional hidden leakage.")

    return clean_df, leakage_features, clean_features


if __name__ == "__main__":
    # Use the clean dataset file
    clean_df, leakage_features, clean_features = analyze_and_clean_dataset('clean_dataset_no_leakage.csv')

    # Save the truly clean dataset
    clean_df.to_csv('truly_clean_dataset.csv', index=False)
    print(f"\n💾 Truly clean dataset saved as: truly_clean_dataset.csv")