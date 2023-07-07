import os
import hashlib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import FeatureHasher

MALWARE_SIGNATURES = {
    'badfile.exe': 1,
    'evilfile.dll': 1,
    'goodfile.exe': 0,
    'legitfile.dll': 0,
}

def calculate_md5(file_path):
    """Calculate the MD5 hash of a file."""
    try:
        with open(file_path, 'rb') as file:
            md5_hash = hashlib.md5()
            while True:
                data = file.read(8192)
                if not data:
                    break
                md5_hash.update(data)
            return md5_hash.hexdigest()
    except IOError:
        return None

def extract_features(file_path):
    """Extract features from a file."""
    # Implement your feature extraction logic here
    # This can include static and dynamic analysis techniques
    md5 = calculate_md5(file_path)
    file_size = os.path.getsize(file_path)
    features = {
        'md5': md5,
        'file_size': file_size,
    }
    return features

def prepare_dataset(directory):
    """Prepare the dataset for machine learning."""
    data = []
    labels = []
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            features = extract_features(file_path)
            if features:
                data.append(features)
                labels.append(MALWARE_SIGNATURES.get(file, 0))
    return data, labels

def train_model(directory):
    """Train a machine learning model."""
    data, labels = prepare_dataset(directory)

    hasher = FeatureHasher(input_type='string')
    hashed_data = hasher.transform(data)

    X_train, X_test, y_train, y_test = train_test_split(
        hashed_data, labels, test_size=0.2, random_state=42
    )

    classifier = RandomForestClassifier()
    classifier.fit(X_train, y_train)

    accuracy = classifier.score(X_test, y_test)
    print(f"Model accuracy: {accuracy}")

def scan_directory(directory):
    """Scan a directory and its subdirectories for files."""
    train_model(directory)

# Example usage
scan_directory('/path/to/directory')
