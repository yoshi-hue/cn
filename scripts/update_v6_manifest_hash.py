import json
from pathlib import Path

from experiments.campaign import source_hash


root = Path("results/campaigns/native-extended-20-v6")
digest = source_hash()
manifest = json.loads((root / "manifest.json").read_text())
manifest["source_hash"] = digest
manifest["working_tree"] = "native campaign driver updated to bypass Docker image check"
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
(root / "source.sha256").write_text(digest + "\n")
print(digest)
