"""
Download large feature matrices from Hugging Face Hub.
Run once after cloning: python setup_data.py
Requires: huggingface_hub (pip install huggingface_hub)
"""
from pathlib import Path
from huggingface_hub import hf_hub_download

REPO_ID = "DarkGusta/cyber-anomaly-features"
DEST = Path(__file__).parent / "notebooks/checkpoints/word2vec"
FILES = ["X_m_w2v.npy", "X_m_w2v_norule.npy"]

DEST.mkdir(parents=True, exist_ok=True)

for filename in FILES:
    dest = DEST / filename
    if dest.exists():
        print(f"Already present: {filename}")
        continue
    print(f"Downloading {filename}...")
    hf_hub_download(
        repo_id=REPO_ID,
        filename=filename,
        repo_type="dataset",
        local_dir=str(DEST),
        token=False,
    )
    print(f"  Saved to {dest}")

print("Done.")
