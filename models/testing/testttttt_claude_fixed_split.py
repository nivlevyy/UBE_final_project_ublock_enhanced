import os

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.metrics import precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
import pickle
# import lightgbm as lgb
if __name__ == '__main__':
    df = pd.read_csv('UPDATED_NAMES_FULLY_FIXED_shuffled_merged_urls_stage1_2_3FULL.csv')
    print(len(df))
    df=df.dropna()
    print(len(df))

    y = df['validity'].map({'safe': 0, 'unsafe': 1})
    columns_to_drop = ['tld', 'SSL Issuer', 'Domain Registrar', 'URL','Hostname Length','Final Domain','Is Email'
       ,'IFrame srcdoc Suspicious Words','URL Length','validity','JS OnMouseOver Scripts'
                     ]

    x = df.drop(columns=columns_to_drop, errors='ignore')
    #
    # softening_factors = {
    #     'URL Length': 0.0001,
    #     'Domain Age': 0.01,
    #     'Domain Expiry': 0.01,
    #     'Resources Total': 0.0016,
    #     'JS Total': 0.1,
    #     'Total Links': 0.01,
    #     'Anchor Different Domains': 0.005,
    #     'VT Reputation': 0.2,
    #     'Anchor Tags': 0.0003,
    #     'Resources':0.085
    # }
    #
    # x=x.clip(lower=-1)
    # for col, factor in softening_factors.items():
    #     if col in x.columns:
    #         x[col] = x[col]*factor


    for col in x.columns:
         x[col] = np.log1p(x[col].clip(lower=0))




    # print(x['Resources Total'].describe())
    # print(df.groupby('validity')['Resources Total'].mean())


    scaler_main  = StandardScaler()
    x_scaled = pd.DataFrame(scaler_main.fit_transform(x), columns=x.columns)
    x_train_scaled, x_test_scaled, y_train_scaled, y_test_scaled = train_test_split(
        x_scaled, y, test_size=0.5, shuffle=True, stratify=y)


    clf= RandomForestClassifier(
        n_estimators=373,
        max_depth=20,
        max_features='sqrt',
        min_samples_split=4,
        min_samples_leaf=2,
        random_state=19,
        class_weight='balanced',
        n_jobs=-1
    )

    clf.fit(x_train_scaled, y_train_scaled)

    threshold = 0.4864
    y_proba = clf.predict_proba(x_test_scaled)[:, 1]
    y_pred = (y_proba >= threshold).astype(int)

    # y_pred = clf.predict(x_test_scaled)
    accuracy = accuracy_score(y_test_scaled, y_pred)


    print(f"Accuracy on test set: {accuracy:.4f}")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test_scaled, y_pred))
    print("Classification Report:")
    print(classification_report(y_test_scaled, y_pred))
    print(precision_recall_fscore_support(y_test_scaled, y_pred,labels=[0,1]))

    importances = clf.feature_importances_
    cols_to_keep = [col for col in x.columns if df[col].nunique() > 1]
    correlations = df[cols_to_keep].corrwith(y).abs()
    mean_diff = df.groupby(y)[x.columns].mean().T
    mean_gap = (mean_diff[1] - mean_diff[0]).abs()

    summary_df = pd.DataFrame({
        'importance': importances ,
        'correlation': correlations,
        'mean_gap': mean_gap
    }).sort_values(by='importance', ascending=False)

    pd.set_option('display.float_format', '{:.6f}'.format)

    pd.set_option('display.max_rows', None)
    print(summary_df)
#
#
#
# selector = SelectFromModel(clf, threshold='median', prefit=True)
# X_selected = selector.transform(x_train_scaled)
# selected_features = x_train_scaled.columns[selector.get_support()]
#
# print("📌 Selected Features:")
# print(selected_features.tolist())
#
# from sklearn.feature_selection import SelectKBest, f_classif
#
# selector = SelectKBest(score_func=f_classif, k=20)  # תבחר את ה־20 הכי טובים
# X_selected_nova = selector.fit_transform(x_train_scaled, y_train_scaled)
# selected_features = x_train_scaled.columns[selector.get_support()]
#
# print("📊 Selected with ANOVA F-test:")
# print(selected_features.tolist())
#
#
#
# from sklearn.feature_selection import mutual_info_classif
#
# mi_scores = mutual_info_classif(x_train_scaled, y_train_scaled)
# mi_series = pd.Series(mi_scores, index=x_train_scaled.columns)
# top_features = mi_series.sort_values(ascending=False).head(30).index.tolist()
#------------------------------------------------------------------------------------------------------------------------
# df = pd.read_csv("UPDATED_NAMES_FULLY_FIXED_shuffled_merged_urls_stage1_2_3FULL.csv")
# y = df['validity'].map({'safe': 0, 'unsafe': 1})
# softening_factors = {
#     'Anchor Tags': 0.0004,
#     'Resources': 0.01,
#     'Resources Total': 0.0015,
#     'Anchor Different Domains': 0.002,
#     'Total Links': 0.003,
#     'JS Total': 0.02,
#     'Domain Age': 0.002,
#     'Anchor Different Domains Ratio': 0.5,
#     'Domain Expiry': 0.002,
#     'Hyphens': 0.5,
# }
#
# # 2. מחק עמודות לא רלוונטיות
# columns_to_drop = ['tld', 'SSL Issuer', 'Domain Registrar', 'URL','Hostname Length',
#                    'Final Domain','Is Email','validity','VT Undetected','VT Suspicious',
#                    'VT Reputation','VT Harmless','VT Malicious','URL Length']
#
# X = df.drop(columns=columns_to_drop, errors='ignore')
#
# # 3. בחר פיצ’רים (לדוגמה: החיתוך בין שתי השיטות)
# selected_features = [
#     'Hyphens', 'Resources', 'favicon Present', 'Anchor Tags',
#     'Anchor Different Domains Ratio', 'External Scripts', 'Total Links',
#     'External Total', 'Resources Total', 'IFrame src', 'IFrame src Different Domains',
#     'IFrame src No Sandbox', 'IFrame External src Ratio', 'IFrame Total',
#     'JS Total', 'JS External', 'JS Different Domains', 'AR Meta Refresh',
#     'Hidden Login Forms'
# ]
#
# X = X[selected_features]
# for col, factor in softening_factors.items():
#     if col in X.columns:
#         X[col] = X[col] * factor
#
# # אופציונלי: Normalization
# X = pd.DataFrame(StandardScaler().fit_transform(X), columns=X.columns)
# # 4. פיצול לאימון ובדיקה
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
#
# # 5. אימון LGBM
# model = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.1, max_depth=6, random_state=42)
# model.fit(X_train, y_train)
#
# # 6. ניבוי וביצועים
# y_pred = model.predict(X_test)
#
# print("🎯 Accuracy:", accuracy_score(y_test, y_pred))
# print("📊 Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
# print("📝 Classification Report:\n", classification_report(y_test, y_pred))

# with open ('model_without_shitty_features.pkl','wb') as f:
#     pickle.dump(clf,f)
#====================================================================================================
#
# df = pd.read_csv('UPDATED_NAMES_FULLY_FIXED_shuffled_merged_urls_stage1_2_3FULL.csv')
#
# y = df['validity'].map({'safe': 0, 'unsafe': 1})
#
# columns_to_drop = ['tld', 'SSL Issuer', 'Domain Registrar', 'URL','Hostname Length','VT Harmless','Final Domain','Is Email','External Metas Ratio','AR Cross Domain','External Scripts','External Scripts Ratio','IFrame srcdoc Suspicious Words'
#     ,'At Signs','validity','URL Length','VT Malicious','Anchor Tags','VT Undetected']
#
#
# x = df.drop(columns=columns_to_drop, errors='ignore')
#
# # softening_factors = {
# #     'URL Length': 0.04,
# #     'VT Malicious': 0.1,
# #     'Number of Directories': 0.25,
# #     'anchor_tags_present': 0.45,
# #     'VT Undetected': 0.2,
# #     'anchor_diff_domain': 1,
# #     'Number of Hyphens': 0.6,
# #     'VT Harmless': 0.3,
# #     'ratio_extern_link': 0.6,
# #     'Length of Hostname': 0.7,
# #     'Resources Total': 0.4,
# #     'Domain Expiration': 0.6
# # }
# #
# # for col, factor in softening_factors.items():
# #     if col in x.columns:
# #         x[col] = x[col] * factor
# # נרמול
# scaler_main  = StandardScaler()
# x_scaled = pd.DataFrame(scaler_main.fit_transform(x), columns=x.columns)
# # חלוקת הנתונים
# x_train_scaled, x_test_scaled, y_train_scaled, y_test_scaled = train_test_split(
#     x_scaled, y, test_size=0.25, shuffle=True, stratify=y)
#
#
#
# clf= RandomForestClassifier(
#     n_estimators=373,
#     max_depth=20,
#     max_features='sqrt',
#     min_samples_split=4,
#     min_samples_leaf=2,
#     random_state=19,
#     class_weight='balanced',
#     n_jobs=-1
# )
#
# clf.fit(x_train_scaled, y_train_scaled)
#
# threshold = 0.4864
# y_proba = clf.predict_proba(x_test_scaled)[:, 1]
# y_pred = (y_proba >= threshold).astype(int)
#
# # y_pred = clf.predict(x_test_scaled)
# accuracy = accuracy_score(y_test_scaled, y_pred)
#
#
# print(f"Accuracy on test set: {accuracy:.4f}")
# print("Confusion Matrix:")
# print(confusion_matrix(y_test_scaled, y_pred))
# print("Classification Report:")
# print(classification_report(y_test_scaled, y_pred))
#
# # ניתוח פיצ'רים
# importances = clf.feature_importances_
# cols_to_keep = [col for col in x.columns if df[col].nunique() > 1]
# correlations = df[cols_to_keep].corrwith(y).abs()
# mean_diff = df.groupby(y)[x.columns].mean().T
# mean_gap = (mean_diff[1] - mean_diff[0]).abs()
#
# summary_df = pd.DataFrame({
#     'importance': importances * 100,
#     'correlation': correlations,
#     'mean_gap': mean_gap
# }).sort_values(by='importance', ascending=False)
#
# pd.set_option('display.float_format', '{:.6f}'.format)
#
# pd.set_option('display.max_rows', None)
# print(summary_df)
#
# with open ('model_version001_importance_less_then_15pre.pkl','wb') as f:
#     pickle.dump(clf,f)