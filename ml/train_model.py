"""Offline LightGBM training utility for HID Shield.

Usage:
    python ml/train_model.py

The script trains a binary LightGBM model on realistic USB-style benign and
malware-family samples and writes the model file to
ml/models/hid_shield_model.txt. Replace synthetic data with real labeled
telemetry when available.
"""

from __future__ import annotations

from pathlib import Path

from lightgbm import Dataset, train
import numpy as np


def _training_data() -> tuple[list[list[float]], list[int], list[float], list[str]]:
    # Feature order:
    # [entropy, file_size, extension_mismatch, has_pe_header,
    #  suspicious_imports_count, yara_matches, is_script,
    #  is_hidden, has_autorun_ref, is_dual_hid]
    x = [
        # Benign USB-style files
        [1.2, 1200, 0, 0, 0, 0, 0, 0, 0, 0],
        [2.0, 4600, 0, 0, 0, 0, 0, 0, 0, 0],
        [3.1, 12000, 0, 0, 0, 0, 1, 0, 0, 0],
        [3.8, 35000, 0, 0, 0, 0, 0, 0, 0, 0],
        [4.6, 72000, 0, 1, 1, 0, 0, 0, 0, 0],
        [4.2, 180000, 0, 0, 0, 0, 0, 0, 0, 1],
        [2.8, 8400, 0, 0, 0, 0, 1, 0, 0, 1],
        [3.4, 22000, 0, 0, 0, 0, 1, 0, 0, 0],
        [2.4, 16000, 0, 0, 0, 0, 0, 0, 0, 0],
        [3.9, 48000, 0, 0, 0, 0, 0, 0, 0, 0],
        # Malware families
        # 1) Ransomware (WannaCry-style)
        [7.9, 3200000, 1, 1, 6, 3, 0, 1, 1, 0],
        [7.7, 2500000, 1, 1, 5, 2, 0, 1, 1, 0],
        # 2) Trojan droppers
        [6.2, 120000, 1, 1, 2, 1, 0, 1, 0, 0],
        [6.9, 240000, 1, 1, 3, 1, 0, 1, 0, 0],
        # 3) BadUSB / HID spoofing payloads
        [6.8, 110000, 0, 0, 1, 1, 1, 1, 1, 1],
        [7.1, 140000, 0, 0, 2, 1, 1, 1, 1, 1],
        # 4) Obfuscated PowerShell / Cobalt Strike
        [7.5, 180000, 0, 0, 1, 2, 1, 1, 1, 1],
        [7.4, 160000, 1, 0, 2, 2, 1, 1, 1, 1],
        # 5) Metasploit shellcode loaders
        [7.3, 350000, 1, 1, 4, 2, 0, 1, 0, 0],
        [7.6, 420000, 1, 1, 5, 2, 0, 1, 0, 0],
        # 6) Keyloggers / stealers
        [6.7, 95000, 1, 1, 3, 1, 1, 1, 0, 1],
        [6.9, 125000, 1, 1, 4, 1, 1, 1, 0, 1],
        # 7) Worm droppers
        [7.8, 1400000, 1, 1, 6, 3, 0, 1, 0, 0],
        [7.6, 980000, 1, 1, 5, 3, 0, 1, 1, 0],
        # 8) Packed executables (high entropy)
        [7.1, 92000, 0, 0, 0, 2, 1, 1, 1, 1],
        [7.6, 110000, 0, 0, 0, 1, 1, 1, 1, 1],
        # 9) Fake documents with macros
        [6.3, 85000, 1, 0, 0, 2, 1, 0, 0, 0],
        [6.6, 102000, 1, 0, 1, 2, 1, 1, 0, 0],
        # 10) LNK + autorun exploits
        [6.9, 76000, 1, 0, 0, 1, 1, 1, 1, 0],
        [7.2, 88000, 1, 0, 1, 2, 1, 1, 1, 0],
        # 11) USB shortcut worms
        [6.8, 64000, 1, 0, 1, 2, 1, 1, 1, 1],
        [7.0, 70000, 1, 0, 2, 2, 1, 1, 1, 1],
        # 12) RAT launcher stagers
        [7.9, 2600000, 1, 1, 7, 3, 0, 1, 0, 0],
        [6.8, 86000, 0, 0, 0, 1, 1, 1, 1, 1],
        [7.4, 440000, 1, 1, 5, 2, 1, 1, 1, 1],
        [6.5, 98000, 0, 0, 0, 1, 1, 1, 1, 0],
    ]
    y = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1,
        1, 1, 1, 1,
    ]

    families = [
        "benign", "benign", "benign", "benign", "benign", "benign", "benign", "benign", "benign", "benign",
        "ransomware_wannacry", "ransomware_wannacry",
        "trojan_dropper", "trojan_dropper",
        "badusb_hid_spoof", "badusb_hid_spoof",
        "powershell_cobaltstrike", "powershell_cobaltstrike",
        "metasploit_shellcode", "metasploit_shellcode",
        "keylogger_stealer", "keylogger_stealer",
        "worm_dropper", "worm_dropper",
        "packed_executable", "packed_executable",
        "macro_document", "macro_document",
        "lnk_autorun_exploit", "lnk_autorun_exploit",
        "usb_shortcut_worm", "usb_shortcut_worm",
        "rat_stager", "rat_stager", "rat_stager", "rat_stager",
    ]

    # More aggressive training: malicious rows get stronger influence.
    sample_weights = [1.0 if label == 0 else 2.6 for label in y]
    return x, y, sample_weights, families


def main() -> None:
    x, y, sample_weights, families = _training_data()

    train_set = Dataset(
        np.asarray(x, dtype=np.float64),
        label=np.asarray(y, dtype=np.float64),
        weight=np.asarray(sample_weights, dtype=np.float64),
        feature_name=[
        "entropy",
        "file_size",
        "extension_mismatch",
        "has_pe_header",
        "suspicious_imports_count",
        "yara_matches",
        "is_script",
        "is_hidden",
        "has_autorun_ref",
        "is_dual_hid",
    ],
    )

    params = {
        "objective": "binary",
        "metric": ["binary_logloss", "auc"],
        "learning_rate": 0.06,
        "num_leaves": 16,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.9,
        "bagging_freq": 1,
        "min_data_in_leaf": 1,
        "min_gain_to_split": 0.0,
        "is_unbalance": True,
        "seed": 42,
        "verbose": -1,
    }
    model = train(params=params, train_set=train_set, num_boost_round=36)

    out_path = Path(__file__).resolve().parent / "models" / "hid_shield_model.txt"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(str(out_path))

    print(f"Model trained and saved to: {out_path}")
    print(f"Samples: total={len(y)} benign={sum(1 for v in y if v == 0)} malicious={sum(1 for v in y if v == 1)}")
    print(f"Malware families covered: {len(set(f for f in families if f != 'benign'))}")

    feature_names = [
        "entropy",
        "file_size",
        "extension_mismatch",
        "has_pe_header",
        "suspicious_imports_count",
        "yara_matches",
        "is_script",
        "is_hidden",
        "has_autorun_ref",
        "is_dual_hid",
    ]

    split_imp = model.feature_importance(importance_type="split")
    gain_imp = model.feature_importance(importance_type="gain")

    ranked = sorted(
        zip(feature_names, split_imp, gain_imp),
        key=lambda item: (item[2], item[1]),
        reverse=True,
    )

    print("\nFeature importance ranking:")
    for idx, (name, split_count, gain_value) in enumerate(ranked, start=1):
        print(f"{idx:>2}. {name:<24} split={int(split_count):>4} gain={float(gain_value):.4f}")


if __name__ == "__main__":
    main()
