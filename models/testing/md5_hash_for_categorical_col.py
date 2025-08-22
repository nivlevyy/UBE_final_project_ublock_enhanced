import hashlib
import numpy as np
import pandas as pd

def md5_hash_index(text, n_features=10):
    text = str(text) if text is not None else "nan"
    digest = hashlib.md5(text.encode()).digest()

    int_hash = int.from_bytes(digest[:4], "little", signed=False)

    index = int_hash % n_features
    sign = -1 if (int_hash & 1) else 1

    return index,sign

def custom_md5_hash_vector(parts, n_features=10):
    vec = np.zeros(n_features, dtype=np.float32)
    for raw in parts:
        index,sign = md5_hash_index(raw, n_features)
        vec[index] += sign
    return vec

# בדיקה
parts = ["www.amazon.com", "GlobalSign nv-sa", "Amazon Registrar, Inc."]
output = custom_md5_hash_vector(parts)
print("✅ MD5-compatible hash:", list(output))
