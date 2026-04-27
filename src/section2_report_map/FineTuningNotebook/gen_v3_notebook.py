"""Emit CSC699LoRA_RAG_v3.ipynb from this module's cell definitions.

Run from repo:
  cd src/section2_report_map/FineTuningNotebook
  python gen_v3_notebook.py
"""
from __future__ import annotations

import json
from pathlib import Path

# Must match AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE in prompts.py byte-for-byte
LOCAL_USER_PROMPT_TEMPLATE = """<s>
### Instruction:
You are a cybersecurity assistant. Your task is to map a normalized finding summary to MITRE ATT&CK Enterprise technique IDs.

Output format: output ONLY a Python list of technique IDs in ATT&CK form, e.g. ['T1190'] or ['T1059.001', 'T1190']. At most 5 IDs. No prose, no JSON, no explanation.

Mapping discipline (critical):
- Distinguish exposure (vulnerable, EOL, misconfiguration, missing patches) from observed adversary behavior (intrusion, malware, C2, credential theft). If the text only describes a weak or EOL public-facing service, prefer Initial Access (e.g. T1190 Exploit Public-Facing Application) when exploitation is plausible, and never invent Command and Control techniques.
- T1102 (Web Service) and sub-techniques are for adversary use of web services for C2 or dead drops. Do NOT map to T1102.x unless the summary clearly describes C2, covert channels, beacons, callbacks, drop resolvers, or similar—not merely HTTP/HTTPS, nginx, or a generic web server.
- Prefer precision over recall. If uncertain, output a shorter list or a single best ID.
- Do not emit sub-technique IDs unless the evidence clearly supports that specificity.

### Reference Examples from Database:
{db_results}

### Log:
{technical_summary}

### Response:
"""


def md(text: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": text.splitlines(keepends=True)}


def code(text: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": text.splitlines(keepends=True),
    }


def build_cells() -> list[dict]:
    cells: list[dict] = []
    mapper_preprocess_src = (
        Path(__file__).resolve().parent / "mapper_preprocess.py"
    ).read_text(encoding="utf-8")

    cells.append(
        md(
            """# CSC699 LoRA Fine-Tuning v3 (full Colab rewrite plan)

Notebook embeds **`mapper_preprocess.py`** (same folder in repo): STIX allowlist, **revoked-by remap**, parent fallback, sorted ID lists, summary normalize, dedupe, **head cap**, **weighted row resample**, tail + inverse-freq dupes, contradictory RAG slice, **production holdout** eval, completion-only SFT, **macro-F1 early stopping**, audit CSV/heatmaps, **marginal collapse plots**, chi-square vs uniform, full per-label metrics export, v2 A/B.

Regenerate: `python gen_v3_notebook.py` (embeds latest `mapper_preprocess.py`).
"""
        )
    )

    cells.append(md("## 1. Environment installs"))
    cells.append(
        code(
            """!pip install -q -U torch transformers datasets accelerate bitsandbytes peft trl sentencepiece protobuf scikit-learn matplotlib pandas scipy scikit-multilearn
"""
        )
    )

    cells.append(md("## 2. Auth & Drive"))
    cells.append(
        code(
            """from huggingface_hub import notebook_login

notebook_login()

from google.colab import drive

drive.mount("/content/drive")

DRIVE_REPO_ROOT = "/content/drive/MyDrive/CSC699/Project/LastMile-Sec"
MAPPED_JSON_DIR = "/content/drive/MyDrive/CSC699/Project/LastMile-Sec/data/mapped"
ATTACK_CORPUS_LOCAL = "/content/drive/MyDrive/CSC699/Project/LastMile-Sec/data/corpus/enterprise-attack-18.1.json"
OUTPUT_DIR = "/content/drive/MyDrive/CSC699/HF/siem-finetuned-v3"
ADAPTER_SAVE_PATH = "/content/drive/MyDrive/CSC699/HF/final_adapter_v3"
# Optional: set to a v2 adapter dir on Drive to compare after training
ADAPTER_V2_COMPARE_PATH = "/content/drive/MyDrive/CSC699/HF/final_adapter_v2"
AUDIT_EXPORT_DIR = "/content/drive/MyDrive/CSC699/HF/training_audit_v3"
"""
        )
    )

    cells.append(
        md(
            """## 3. Preprocessing library (embedded `mapper_preprocess.py`)

Deliverable from plan (module extract). Contains: STIX download/load, allowlist, **revoked-by** remap, **parent fallback** for sub-techniques, sorted label lists, summary normalization, dedupe/cap/weight helpers, tail oversample helpers."""
        )
    )
    cells.append(
        code(
            "# --- Begin mapper_preprocess.py (repo: FineTuningNotebook/mapper_preprocess.py) ---\n"
            + mapper_preprocess_src
            + "\n# --- End mapper_preprocess.py ---\n"
        )
    )
    cells.append(
        md(
            """## 4. Imports, seeds, ATT&CK init, run knobs

Call `load_attack_bundle` after paths from Sec. 2 exist."""
        )
    )
    cells.append(
        code(
            r"""import ast
import csv
import hashlib
import json
import math
import random
import re
import subprocess
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from datasets import Dataset, concatenate_datasets, load_dataset
from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training
from scipy.stats import chisquare
from sklearn.metrics import classification_report, f1_score, precision_recall_fscore_support
from sklearn.preprocessing import MultiLabelBinarizer
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, EarlyStoppingCallback
from trl import SFTConfig, SFTTrainer

RAG_FRACTION = 0.18
CONTRADICTORY_RAG_FRACTION = 0.025
SEED = 42
MAX_ROWS_PER_TAG = 450
RARE_TAG_THRESHOLD = 80
TAIL_MAX_DUPES_PER_ROW = 12
INVERSE_FREQ_MAX_EXTRA = 3
USE_WEIGHTED_ROW_RESAMPLE = True
PRODUCTION_HOLDOUT_FRAC = 0.15
EXTERNAL_CORPUS_JSONL = None  # optional: path on Drive to JSONL with keys text,mitre_tags (list)
TAIL_RECALL_K = 25

random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

set_max_techniques(5)
load_attack_bundle(
    ATTACK_CORPUS_LOCAL if Path(ATTACK_CORPUS_LOCAL).is_file() else None
)
print("ATTACK_VERSION:", ATTACK_VERSION, "| Allowlist size:", len(ALLOWLIST))
"""
        )
    )

    cells.append(
        md(
            """## 5. Load dataset, audit, invalid-tag rate, co-occurrence **heatmap** (raw)

**Anti-clustering:** inspect long-tail structure before normalization. Filtered label CSV is written in Sec. 6 after remap + cap."""
        )
    )
    cells.append(
        code(
            r"""import matplotlib.pyplot as plt

Path(AUDIT_EXPORT_DIR).mkdir(parents=True, exist_ok=True)

print("Loading tumeteor/Security-TTP-Mapping ...")
ds_raw = load_dataset("tumeteor/Security-TTP-Mapping")
ds_raw = ds_raw.rename_column("labels", "mitre_tags")
print(ds_raw["train"].features)
for i in range(3):
    row = ds_raw["train"][i]
    print("--- sample", i, "---")
    print("text1 (prefix):", (row.get("text1") or "")[:220].replace("\n", " "), "...")
    print("mitre_tags raw:", row.get("mitre_tags"))

flat_raw = []
for row in ds_raw["train"]:
    for t in row["mitre_tags"] or []:
        flat_raw.append(str(t).upper())
hist_raw = Counter(flat_raw)
print("Unique raw tags (train):", len(hist_raw))
print("Top 15 raw tags:", hist_raw.most_common(15))

bad0, tot0, rate0 = raw_tag_invalid_rate_from_hf(ds_raw["train"], mitre_key="mitre_tags", limit=8000)
print(
    "Raw tag invalid rate (sample, pre-normalize):",
    f"{rate0:.4f}",
    f"({bad0}/{tot0})",
)
print("ATTACK_VERSION:", ATTACK_VERSION)

# Co-occurrence heatmap (top-K frequent tags, train split, sampled pairs)
K_CO = 28
top_tags = [t for t, _ in hist_raw.most_common(K_CO)]
tag_i = {t: i for i, t in enumerate(top_tags)}
mat = np.zeros((K_CO, K_CO), dtype=np.float32)
for row in ds_raw["train"]:
    ts = sorted({str(x).upper() for x in (row.get("mitre_tags") or []) if str(x).upper() in tag_i})
    for a in range(len(ts)):
        for b in range(a + 1, len(ts)):
            i, j = tag_i[ts[a]], tag_i[ts[b]]
            mat[i, j] += 1
            mat[j, i] += 1
fig, ax = plt.subplots(figsize=(10, 8))
im = ax.imshow(mat, cmap="Blues")
ax.set_xticks(range(K_CO))
ax.set_yticks(range(K_CO))
ax.set_xticklabels(top_tags, rotation=90, fontsize=7)
ax.set_yticklabels(top_tags, fontsize=7)
ax.set_title("Co-occurrence (raw labels, top-%d tags, train)" % K_CO)
plt.colorbar(im, ax=ax, fraction=0.046)
plt.tight_layout()
plt.savefig(str(Path(AUDIT_EXPORT_DIR) / "cooccurrence_raw_top_tags.png"), dpi=120)
plt.show()
print("Saved:", Path(AUDIT_EXPORT_DIR) / "cooccurrence_raw_top_tags.png")
"""
        )
    )

    cells.append(
        md(
            """## 6. Filter, **dedupe**, **head cap**, optional **weighted resample**, tail + inverse-rarity

Uses **`mapper_preprocess`**: `dedupe_by_content`, `cap_rows_per_tag`, `weighted_resample_dataset`, `oversample_tail`, `inverse_frequency_dupes`. Validation stays unweighted."""
        )
    )
    cells.append(
        code(
            r"""def attach_normalized(example):
    tags = normalize_tag_list(list(example["mitre_tags"] or []))
    text_norm = normalize_summary_text(example.get("text1") or "")
    return {"tags_norm": tags, "text1_norm": text_norm}

train_ft = ds_raw["train"].map(attach_normalized)
val_ft = ds_raw["validation"].map(attach_normalized)
train_ft = train_ft.filter(lambda ex: len(ex["tags_norm"]) > 0)
val_ft = val_ft.filter(lambda ex: len(ex["tags_norm"]) > 0)

print("Label cardinality (train, pre-rebalance):", tag_cardinality_stats(train_ft))

train_ft = dedupe_by_content(train_ft)
print("Train rows after dedupe:", len(train_ft))

train_ft = cap_rows_per_tag(train_ft, MAX_ROWS_PER_TAG, seed=SEED)
hist_n = Counter(t for row in train_ft for t in row["tags_norm"])

if USE_WEIGHTED_ROW_RESAMPLE:
    train_ft = weighted_resample_dataset(train_ft, seed=SEED)
    print("Applied weighted_resample_dataset (inverse sqrt tag frequency).")

train_ft = oversample_tail(train_ft, TAIL_MAX_DUPES_PER_ROW, RARE_TAG_THRESHOLD, seed=SEED)
train_ft = inverse_frequency_dupes(train_ft, INVERSE_FREQ_MAX_EXTRA, seed=SEED)
print("Train rows after tail + inverse-freq dupes:", len(train_ft))

csv_path = Path(AUDIT_EXPORT_DIR) / "label_counts_train_filtered.csv"
with open(csv_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["technique_id", "row_count_tag_in_train"])
    hist_final = Counter(t for row in train_ft for t in row["tags_norm"])
    for tid, c in hist_final.most_common():
        w.writerow([tid, c])
print("Wrote", csv_path)
print("Top 15 normalized tags (post rebalance):", hist_final.most_common(15))

try:
    from skmultilearn.model_selection import IterativeStratification

    print(
        "skmultilearn: IterativeStratification available (use for custom multi-label splits if you merge pools)."
    )
except Exception as _e:
    print("skmultilearn optional import:", _e)
"""
        )
    )

    cells.append(
        md(
            """## 7. Production template + alignment check

**Anti-clustering:** byte match with `prompts.py` avoids instruction skew."""
        )
    )
    cells.append(
        code(
            "NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE = "
            + repr(LOCAL_USER_PROMPT_TEMPLATE)
            + "\n\n"
            + r"""def extract_local_template_from_prompts_py(repo_root):
    path = Path(repo_root) / "src" / "section2_report_map" / "prompts.py"
    if not path.is_file():
        raise FileNotFoundError(path)
    mod = ast.parse(path.read_text(encoding="utf-8"))
    for node in mod.body:
        if not isinstance(node, ast.ClassDef) or node.name != "AttackMapperPrompts":
            continue
        for sub in node.body:
            if isinstance(sub, ast.Assign) and isinstance(sub.targets[0], ast.Name):
                if sub.targets[0].id == "LOCAL_USER_PROMPT_TEMPLATE":
                    return sub.value.value
    raise ValueError("LOCAL_USER_PROMPT_TEMPLATE not found in prompts.py")

try:
    repo_tpl = extract_local_template_from_prompts_py(DRIVE_REPO_ROOT)
except Exception as e:
    print("Alignment check skipped:", e)
else:
    if repo_tpl != NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE:
        import difflib
        diff = difflib.unified_diff(
            repo_tpl.splitlines(),
            NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.splitlines(),
            lineterm="",
            fromfile="prompts.py",
            tofile="notebook",
        )
        raise ValueError("Training template diverges from production:\n" + "\n".join(diff))
    print("OK: notebook matches AttackMapperPrompts.LOCAL_USER_PROMPT_TEMPLATE.")
"""
        )
    )

    cells.append(
        md(
            """## 8. Synthetic RAG (+ **contradictory** slice) + `prompt` / `completion`

**Contradictory RAG:** a small fraction of rows inject verified-looking examples with **wrong** MITRE IDs so the model must rely on the summary, not copy retrieved IDs."""
        )
    )
    cells.append(
        code(
            r"""EMPTY_DB = "No verified historical examples were found."


def build_tag_cooccurrence_index(dataset):
    idxs = defaultdict(list)
    for i, row in enumerate(dataset):
        for t in row["tags_norm"]:
            idxs[t].append(i)
    return idxs

TAG_TO_ROWS = build_tag_cooccurrence_index(train_ft)


def sample_db_results_train(example, row_index):
    tags = example["tags_norm"]
    if tags and random.random() < CONTRADICTORY_RAG_FRACTION:
        pool = [t for t in ALLOWLIST if t not in set(tags)]
        if len(pool) >= 2:
            wrong = random.sample(pool, k=min(3, len(pool)))
            snippet = ((example.get("text1_norm") or "").strip()[:120] or "Unrelated.") + " [contradictory RAG]"
            ids_literal = format_mitre_list(wrong).strip()
            return (
                f"1. Summary: {snippet}\n"
                f"   Verified MITRE IDs: {ids_literal} (similarity=0.850)"
            )
    if random.random() > RAG_FRACTION:
        return EMPTY_DB
    candidates = []
    for t in tags:
        for j in TAG_TO_ROWS.get(t, []):
            if j != row_index:
                candidates.append(j)
    if not candidates:
        return EMPTY_DB
    partner = train_ft[random.choice(candidates)]
    snippet = (partner.get("text1_norm") or "").strip()[:200]
    cur = (example.get("text1_norm") or "").strip()[:200]
    if snippet == cur:
        return EMPTY_DB
    ids_literal = format_mitre_list(tags).strip()
    return f"1. Summary: {snippet}...\n   Verified MITRE IDs: {ids_literal} (similarity=0.850)"


def row_to_train_pc(example, idx):
    summary = (example.get("text1_norm") or "").strip()
    db = sample_db_results_train(example, int(idx))
    prompt = NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.format(db_results=db, technical_summary=summary)
    return {"prompt": prompt, "completion": format_mitre_list(example["tags_norm"])}


def row_to_val_pc(example, idx):
    summary = (example.get("text1_norm") or "").strip()
    prompt = NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.format(db_results=EMPTY_DB, technical_summary=summary)
    return {"prompt": prompt, "completion": format_mitre_list(example["tags_norm"])}

train_pc = train_ft.map(row_to_train_pc, with_indices=True, remove_columns=train_ft.column_names)
val_pc = val_ft.map(row_to_val_pc, with_indices=True, remove_columns=val_ft.column_names)
print("Sample completion:", repr(train_pc[0]["completion"]))
"""
        )
    )

    cells.append(
        md(
            """## 9. Optional `data/mapped` shard + **production holdout**

Mapped JSON rows are split: **`PRODUCTION_HOLDOUT_FRAC`** stays out of `train_pc` for honest production-style eval (Sec. 14 / holdout block)."""
        )
    )
    cells.append(
        code(
            r"""ENABLE_MAPPED_SHARD = True
PRODUCTION_SHARD_REPEATS = 4


def parse_raw_output_ids(raw):
    raw = raw or ""
    m = re.search(r"\[[^\]]*\]", raw)
    if not m:
        return []
    try:
        v = ast.literal_eval(m.group(0))
        if isinstance(v, list):
            return [str(x).upper() for x in v if x]
    except Exception:
        pass
    return []


def semantic_removed_all_ids(mapping):
    raw_ids = parse_raw_output_ids(mapping.get("raw_model_output") or "")
    final = [str(x).upper() for x in (mapping.get("mitre_ids") or []) if x]
    if not raw_ids or final:
        return False
    for issue in mapping.get("validation_issues") or []:
        if issue.get("gate") == "semantic":
            return True
    return False


def load_mapped_training_rows(mapped_dir):
    rows = []
    root = Path(mapped_dir)
    if not root.is_dir():
        print("Mapped dir missing:", mapped_dir)
        return rows
    for path in sorted(root.glob("*.json")):
        try:
            packet = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        for finding in packet.get("findings", []):
            meta = finding.get("metadata") or {}
            mapping = meta.get("mitre_mapping") or {}
            if not mapping.get("validation_passed", False):
                continue
            if semantic_removed_all_ids(mapping):
                continue
            mids = normalize_tag_list([str(x) for x in (mapping.get("mitre_ids") or []) if x])
            if not mids or len(mids) > MAX_TECHNIQUES_PER_FINDING:
                continue
            summary = normalize_summary_text(meta.get("technical_summary") or "")
            if not summary:
                continue
            rows.append({"text1_norm": summary, "tags_norm": mids})
    print("Production mapped rows:", len(rows))
    return rows


def row_to_train_from_mapped(example, idx):
    summary = (example.get("text1_norm") or "").strip()
    prompt = NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.format(db_results=EMPTY_DB, technical_summary=summary)
    return {"prompt": prompt, "completion": format_mitre_list(example["tags_norm"])}

prod_rows_all = load_mapped_training_rows(MAPPED_JSON_DIR) if ENABLE_MAPPED_SHARD else []
prod_holdout_pc = None
prod_train_rows = []
if prod_rows_all:
    rng_m = random.Random(SEED)
    shuf = prod_rows_all[:]
    rng_m.shuffle(shuf)
    n_hold = int(len(shuf) * PRODUCTION_HOLDOUT_FRAC) if PRODUCTION_HOLDOUT_FRAC > 0 else 0
    hold_list, prod_train_rows = shuf[:n_hold], shuf[n_hold:]
    print(
        "Mapped split: production holdout rows =",
        len(hold_list),
        "| train shard rows =",
        len(prod_train_rows),
    )
    if hold_list:
        hod = Dataset.from_list(hold_list)
        prod_holdout_pc = hod.map(
            row_to_train_from_mapped, with_indices=True, remove_columns=hod.column_names
        )
if prod_train_rows:
    prod_ds = Dataset.from_list(prod_train_rows)
    prod_pc = prod_ds.map(row_to_train_from_mapped, with_indices=True, remove_columns=prod_ds.column_names)
    train_pc = concatenate_datasets([train_pc] + [prod_pc] * PRODUCTION_SHARD_REPEATS).shuffle(
        seed=SEED
    )
    print("Train rows after mapped shard:", len(train_pc))

if EXTERNAL_CORPUS_JSONL and Path(EXTERNAL_CORPUS_JSONL).is_file():
    ext_rows = []
    with open(EXTERNAL_CORPUS_JSONL, encoding="utf-8") as ef:
        for line in ef:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            summ = normalize_summary_text(o.get("text") or o.get("text1") or "")
            tags = normalize_tag_list(list(o.get("mitre_tags") or o.get("labels") or []))
            if summ and tags:
                ext_rows.append({"text1_norm": summ, "tags_norm": tags})
    if ext_rows:
        ed = Dataset.from_list(ext_rows)
        ext_pc = ed.map(row_to_train_from_mapped, with_indices=True, remove_columns=ed.column_names)
        train_pc = concatenate_datasets([train_pc, ext_pc]).shuffle(seed=SEED)
        print("External JSONL rows merged:", len(ext_rows), "| train_pc:", len(train_pc))
"""
        )
    )

    cells.append(md("## 10. Model + LoRA"))
    cells.append(
        code(
            r"""model_id = "mistralai/Mistral-7B-Instruct-v0.1"

nf4_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.bfloat16,
)

tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
tokenizer.pad_token = tokenizer.eos_token
tokenizer.padding_side = "right"

model = AutoModelForCausalLM.from_pretrained(
    model_id,
    quantization_config=nf4_config,
    device_map="auto",
    trust_remote_code=True,
)

model.gradient_checkpointing_enable()
model = prepare_model_for_kbit_training(model)

peft_config = LoraConfig(
    r=16,
    lora_alpha=16,
    target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type="CAUSAL_LM",
)
model = get_peft_model(model, peft_config)
model.print_trainable_parameters()
"""
        )
    )

    cells.append(
        md(
            """## 11. **Macro-F1 SFTTrainer** + early stopping on `eval_macro_f1`

Runs a small generation pass on `eval_dataset` each `evaluate` call to compute **macro-F1** (subset for speed). `metric_for_best_model` drives checkpointing and `EarlyStoppingCallback`."""
        )
    )
    cells.append(
        code(
            r"""LABEL_VOCAB = sorted({t for row in val_ft for t in row["tags_norm"]})
MACRO_F1_EVAL_SAMPLES = 220


def parse_id_list(text):
    m = re.search(r"\[[^\]]*\]", text)
    if not m:
        return []
    try:
        v = ast.literal_eval(m.group(0))
        if isinstance(v, list):
            return [str(x).upper() for x in v]
    except Exception:
        pass
    return []


def multilabel_f1(golds, preds, all_labels):
    from sklearn.metrics import f1_score
    from sklearn.preprocessing import MultiLabelBinarizer

    mlb = MultiLabelBinarizer(classes=all_labels)
    Y = mlb.fit_transform([set(g) for g in golds])
    Yhat = mlb.transform([set(p) for p in preds])
    micro = f1_score(Y, Yhat, average="micro", zero_division=0)
    macro = f1_score(Y, Yhat, average="macro", zero_division=0)
    return micro, macro


def generation_macro_f1(trainer, n_samples):
    model = trainer.model
    tok = trainer.processing_class
    ds = trainer.eval_dataset
    n = min(n_samples, len(ds))
    golds = [val_ft[i]["tags_norm"] for i in range(n)]
    preds = []
    model.eval()
    device = next(model.parameters()).device
    for i in range(n):
        prompt = ds[i]["prompt"]
        inputs = tok(prompt, return_tensors="pt").to(device)
        with torch.inference_mode():
            out = model.generate(
                **inputs,
                max_new_tokens=64,
                do_sample=False,
                pad_token_id=tok.pad_token_id,
                eos_token_id=tok.eos_token_id,
            )
        gen = tok.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
        preds.append(parse_id_list(gen))
    _, macro = multilabel_f1(golds, preds, LABEL_VOCAB)
    return macro


class MacroF1SFTTrainer(SFTTrainer):
    def evaluate(self, eval_dataset=None, ignore_keys=None, metric_key_prefix="eval"):
        metrics = super().evaluate(eval_dataset, ignore_keys, metric_key_prefix)
        try:
            macro = generation_macro_f1(self, MACRO_F1_EVAL_SAMPLES)
        except Exception as e:
            print("macro-F1 eval skipped:", e)
            macro = 0.0
        metrics["eval_macro_f1"] = macro
        print("eval_macro_f1:", round(macro, 4))
        return metrics


args = SFTConfig(
    output_dir=OUTPUT_DIR,
    max_seq_length=1024,
    max_steps=2400,
    per_device_train_batch_size=4,
    gradient_accumulation_steps=8,
    warmup_steps=100,
    logging_steps=50,
    eval_strategy="steps",
    eval_steps=200,
    save_strategy="steps",
    save_steps=200,
    save_total_limit=5,
    learning_rate=3e-5,
    bf16=True,
    lr_scheduler_type="cosine",
    completion_only_loss=True,
    load_best_model_at_end=True,
    metric_for_best_model="eval_macro_f1",
    greater_is_better=True,
    report_to=[],
)

trainer = MacroF1SFTTrainer(
    model=model,
    processing_class=tokenizer,
    args=args,
    train_dataset=train_pc,
    eval_dataset=val_pc,
    callbacks=[EarlyStoppingCallback(early_stopping_patience=2)],
)
print("Trainer ready; best checkpoint by eval_macro_f1.")
"""
        )
    )

    cells.append(md("## 12. Debug batch (`-100` masking)"))
    cells.append(
        code(
            r"""batch = next(iter(trainer.get_train_dataloader()))
labels = batch["labels"][0].tolist()
print("First 80 labels:", labels[:80])
if labels[:40].count(-100) < 20:
    print("WARNING: early positions not mostly -100")
else:
    print("OK: prompt region mostly masked.")
"""
        )
    )

    cells.append(md("## 13. Train + save"))
    cells.append(
        code(
            r"""trainer.train()
trainer.model.save_pretrained(ADAPTER_SAVE_PATH)
tokenizer.save_pretrained(ADAPTER_SAVE_PATH)


def _git_head(repo_root: str):
    try:
        return subprocess.check_output(
            ["git", "-C", str(Path(repo_root)), "rev-parse", "HEAD"],
            text=True,
            timeout=8,
        ).strip()
    except Exception:
        return None


manifest = {
    "attack_version": ATTACK_VERSION,
    "max_techniques": MAX_TECHNIQUES_PER_FINDING,
    "completion_only_loss": True,
    "metric_for_best_model": "eval_macro_f1",
    "rag_fraction": RAG_FRACTION,
    "contradictory_rag_fraction": CONTRADICTORY_RAG_FRACTION,
    "use_weighted_row_resample": USE_WEIGHTED_ROW_RESAMPLE,
    "production_holdout_frac": PRODUCTION_HOLDOUT_FRAC,
    "max_rows_per_tag": MAX_ROWS_PER_TAG,
    "deprecation_remap_size": len(DEPRECATION_REMAP),
    "train_rows": len(train_pc),
    "val_rows": len(val_pc),
    "prompt_template_sha256": hashlib.sha256(
        NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.encode("utf-8")
    ).hexdigest(),
    "git_commit": _git_head(DRIVE_REPO_ROOT),
}
Path(ADAPTER_SAVE_PATH).mkdir(parents=True, exist_ok=True)
(Path(ADAPTER_SAVE_PATH) / "training_manifest.json").write_text(
    json.dumps(manifest, indent=2), encoding="utf-8"
)
print("Saved:", ADAPTER_SAVE_PATH)
"""
        )
    )

    cells.append(
        md(
            """## 14. Full eval: micro/macro, **top1**, **KL**, **χ² vs uniform**, **marginals**, **tail_recall@K**, per-label **P/R/F1 CSV**, mispairs"""
        )
    )
    cells.append(
        code(
            r"""def kl_divergence(p, q, eps=1e-12):
    # KL-like divergence of normalized mass over shared keys.
    keys = sorted(set(p.keys()) | set(q.keys()))
    a = np.array([p.get(k, 0) + eps for k in keys], dtype=np.float64)
    b = np.array([q.get(k, 0) + eps for k in keys], dtype=np.float64)
    a /= a.sum()
    b /= b.sum()
    return float(np.sum(a * np.log(a / b)))

EVAL_N = min(500, len(val_pc))
preds, golds = [], [val_ft[i]["tags_norm"] for i in range(EVAL_N)]
model.eval()
device = next(model.parameters()).device
for i in range(EVAL_N):
    inputs = tokenizer(val_pc[i]["prompt"], return_tensors="pt").to(device)
    with torch.inference_mode():
        out = model.generate(
            **inputs,
            max_new_tokens=64,
            do_sample=False,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    gen = tokenizer.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
    preds.append(parse_id_list(gen))

micro, macro = multilabel_f1(golds, preds, LABEL_VOCAB)
flat_pred = [p for row in preds for p in row]
flat_gold = [p for row in golds for p in row]
ctr_p = Counter(flat_pred)
ctr_g = Counter(flat_gold)
top1_fraction = ctr_p.most_common(1)[0][1] / len(flat_pred) if flat_pred else float("nan")
uniq_pred = len(ctr_p)
# Shannon entropy of prediction mass (higher = less collapse)
probs = np.array(list(ctr_p.values()), dtype=np.float64)
probs = probs / probs.sum()
entropy = float(-np.sum(probs * np.log(probs + 1e-12)))
pg = {k: v / len(flat_gold) for k, v in ctr_g.items()} if flat_gold else {}
pp = {k: v / len(flat_pred) for k, v in ctr_p.items()} if flat_pred else {}
kl_pg = kl_divergence(pp, pg) if flat_pred and flat_gold else float("nan")

import matplotlib.pyplot as plt

train_hist = Counter(t for row in train_ft for t in row["tags_norm"])
rare_cut = 50
rare_labels = {t for t, c in train_hist.items() if c < rare_cut}
tail_hits = sum(
    1 for gset, pset in zip(golds, preds) for g in gset if g in rare_labels and g in set(pset)
)
tail_possible = sum(1 for row in golds for g in row if g in rare_labels)
tail_recall = tail_hits / tail_possible if tail_possible else float("nan")

rare_k_list = sorted(train_hist.keys(), key=lambda t: train_hist[t])[: max(1, int(TAIL_RECALL_K))]
rare_k = set(rare_k_list)
tailk_hits = sum(
    1 for gset, pset in zip(golds, preds) for g in gset if g in rare_k and g in set(pset)
)
tailk_possible = sum(1 for row in golds for g in row if g in rare_k)
tail_recall_at_k = tailk_hits / tailk_possible if tailk_possible else float("nan")

top_m = min(40, len(ctr_p))
chi_stat, chi_p = float("nan"), float("nan")
if top_m > 1 and flat_pred:
    top_pred_tags = [t for t, _ in ctr_p.most_common(top_m)]
    obs = np.array([float(ctr_p[t]) for t in top_pred_tags], dtype=np.float64)
    exp = np.full_like(obs, obs.sum() / len(obs))
    if obs.sum() > 0:
        chi_stat, chi_p = chisquare(obs, f_exp=exp)

pair_miss = Counter()
for gset, pset in zip(golds, preds):
    gset, pset = set(gset), set(pset)
    for g in gset - pset:
        for p in pset - gset:
            pair_miss[(g, p)] += 1

mlb_full = MultiLabelBinarizer(classes=LABEL_VOCAB)
Y_bin = mlb_full.fit_transform([set(g) for g in golds])
Yhat_bin = mlb_full.transform([set(p) for p in preds])
prec_a, rec_a, f1_a, sup_a = precision_recall_fscore_support(
    Y_bin, Yhat_bin, average=None, zero_division=0
)
prf_path = Path(AUDIT_EXPORT_DIR) / "per_label_prf1_val.csv"
with open(prf_path, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["technique_id", "support", "precision", "recall", "f1"])
    for i, tid in enumerate(LABEL_VOCAB):
        w.writerow([tid, int(sup_a[i]), float(prec_a[i]), float(rec_a[i]), float(f1_a[i])])
print("Wrote", prf_path)

per_rows = sorted(
    [(LABEL_VOCAB[i], float(f1_a[i]), int(sup_a[i])) for i in range(len(LABEL_VOCAB))],
    key=lambda x: x[1],
)
print("=== Collapse / diversity ===")
print(f"micro-F1: {micro:.4f}  macro-F1: {macro:.4f}  top1_fraction: {top1_fraction:.4f}")
print(f"unique_predicted_ids: {uniq_pred}  pred_entropy: {entropy:.4f}  KL(pred||gold): {kl_pg:.4f}")
print(
    f"tail_recall (gold in rare train-freq<{rare_cut}): {tail_recall:.4f} ({tail_hits}/{tail_possible})"
)
print(
    f"tail_recall@K (K={len(rare_k)} rarest train tags): {tail_recall_at_k:.4f} ({tailk_hits}/{tailk_possible})"
)
print(f"chi-square vs uniform (top-{top_m} pred tags): stat={chi_stat:.4f} p={chi_p:.4e}")

top_n = 20
show_tags = sorted(
    set(ctr_g.keys()) | set(ctr_p.keys()),
    key=lambda t: -(ctr_g.get(t, 0) + ctr_p.get(t, 0)),
)[:top_n]
if show_tags:
    xg = np.arange(len(show_tags))
    fig, ax = plt.subplots(figsize=(12, 4))
    ax.bar(xg - 0.2, [ctr_g.get(t, 0) for t in show_tags], width=0.4, label="gold")
    ax.bar(xg + 0.2, [ctr_p.get(t, 0) for t in show_tags], width=0.4, label="pred")
    ax.set_xticks(xg)
    ax.set_xticklabels(show_tags, rotation=90, fontsize=7)
    ax.legend()
    ax.set_title("Marginal tag counts (val subset): gold vs predicted")
    fig.tight_layout()
    marg_path = Path(AUDIT_EXPORT_DIR) / "marginal_gold_vs_pred.png"
    fig.savefig(str(marg_path), dpi=120)
    plt.show()
    print("Saved:", marg_path)

print("Top misprediction (gold,pred) pairs:", pair_miss.most_common(12))
print("Lowest per-technique F1 (all labels in vocab):", per_rows[:15])
print("Highest per-technique F1 (sample):", per_rows[-10:])

fail = {"empty_parse": 0, "only_head_tag": 0}
head5 = {t for t, _ in train_hist.most_common(5)}
for g, p in zip(golds, preds):
    if not p:
        fail["empty_parse"] += 1
    elif len(set(p)) == 1 and p[0] in head5 and set(g) != set(p):
        fail["only_head_tag"] += 1
print("Failure buckets:", fail)

if prod_holdout_pc is not None and len(prod_holdout_pc) > 0:
    HN = min(300, len(prod_holdout_pc))
    ph_gold = [parse_id_list(prod_holdout_pc[i]["completion"]) for i in range(HN)]
    ph_pred = []
    for i in range(HN):
        inputs = tokenizer(prod_holdout_pc[i]["prompt"], return_tensors="pt").to(device)
        with torch.inference_mode():
            out = model.generate(
                **inputs,
                max_new_tokens=64,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        gen = tokenizer.decode(
            out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True
        )
        ph_pred.append(parse_id_list(gen))
    mi_h, ma_h = multilabel_f1(ph_gold, ph_pred, LABEL_VOCAB)
    print(f"Production holdout ({HN} rows): micro={mi_h:.4f} macro={ma_h:.4f}")
else:
    print("Production holdout: none (enable mapped shard + data).")
"""
        )
    )

    cells.append(md("## 15. Optional **v2 vs v3** A/B (same val prompts)"))
    cells.append(
        code(
            r"""RUN_V2_COMPARE = Path(ADAPTER_V2_COMPARE_PATH).is_dir()


def eval_adapter_on_val(adapter_path, label, n=min(200, len(val_pc))):
    if not Path(adapter_path).is_dir():
        print("Skip", label, "- not found")
        return
    base = AutoModelForCausalLM.from_pretrained(
        model_id,
        quantization_config=nf4_config,
        device_map="auto",
        trust_remote_code=True,
    )
    m = PeftModel.from_pretrained(base, adapter_path)
    m.eval()
    device = next(m.parameters()).device
    preds_local = []
    golds_local = [val_ft[i]["tags_norm"] for i in range(n)]
    for i in range(n):
        inputs = tokenizer(val_pc[i]["prompt"], return_tensors="pt").to(device)
        with torch.inference_mode():
            out = m.generate(
                **inputs,
                max_new_tokens=64,
                do_sample=False,
                pad_token_id=tokenizer.pad_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
        gen = tokenizer.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True)
        preds_local.append(parse_id_list(gen))
    mi, ma = multilabel_f1(golds_local, preds_local, LABEL_VOCAB)
    flat = [p for row in preds_local for p in row]
    c = Counter(flat)
    t1 = c.most_common(1)[0][1] / len(flat) if flat else float("nan")
    print(f"{label}: micro={mi:.4f} macro={ma:.4f} top1_fraction={t1:.4f}")
    del m
    del base
    torch.cuda.empty_cache()

if RUN_V2_COMPARE:
    eval_adapter_on_val(ADAPTER_V2_COMPARE_PATH, "v2_adapter")
    eval_adapter_on_val(ADAPTER_SAVE_PATH, "v3_adapter")
else:
    print("Set ADAPTER_V2_COMPARE_PATH to a v2 adapter directory to run A/B.")
"""
        )
    )

    cells.append(md("## 16. Smoke test"))
    cells.append(
        code(
            r"""smoke_prompt = NOTEBOOK_LOCAL_USER_PROMPT_TEMPLATE.format(
    db_results=EMPTY_DB,
    technical_summary=(
        "A connection from 10.128.1.13 to 192.168.220.132 on port 3389 (RDP) indicates suspicious remote desktop activity."
    ),
)
inputs = tokenizer(smoke_prompt, return_tensors="pt").to(model.device)
with torch.inference_mode():
    out = model.generate(
        **inputs,
        max_new_tokens=50,
        do_sample=False,
        pad_token_id=tokenizer.pad_token_id,
        eos_token_id=tokenizer.eos_token_id,
    )
print(tokenizer.decode(out[0][inputs["input_ids"].shape[1] :], skip_special_tokens=True))
"""
        )
    )

    cells.append(
        md(
            """## Plan checklist (implemented in-notebook)

| Item | Where |
|------|--------|
| Embedded **`mapper_preprocess.py`** | Sec. 3 |
| Imports, seeds, `load_attack_bundle`, knobs | Sec. 4 |
| Audit, invalid-tag rate, raw co-occurrence heatmap | Sec. 5 |
| Dedupe, head cap, **weighted resample**, tail, inverse-freq | Sec. 6 (`mapper_preprocess`) |
| Production prompt + diff | Sec. 7 |
| RAG + **contradictory RAG** + prompt/completion | Sec. 8 |
| Mapped shard + **production holdout** + optional external JSONL | Sec. 9 |
| Model + LoRA | Sec. 10 |
| Macro-F1 trainer + early stopping | Sec. 11 |
| Debug `-100` batch | Sec. 12 |
| Train + save + **manifest** (git hash, template hash) | Sec. 13 |
| Eval: KL, chi-square, marginals, **tail@K**, full **P/R/F1 CSV**, holdout metrics | Sec. 14 |
| v2 A/B | Sec. 15 |
| Smoke | Sec. 16 |

Repo source for the embedded module: `FineTuningNotebook/mapper_preprocess.py`. Regenerate this notebook with `python gen_v3_notebook.py`.
"""
        )
    )

    return cells


def main() -> None:
    out_path = Path(__file__).resolve().parent / "CSC699LoRA_RAG_v3.ipynb"
    nb = {
        "cells": build_cells(),
        "metadata": {
            "kernelspec": {
                "display_name": "Python 3",
                "language": "python",
                "name": "python3",
            },
            "language_info": {"name": "python"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }
    out_path.write_text(json.dumps(nb, indent=1), encoding="utf-8")
    print("Wrote", out_path)


if __name__ == "__main__":
    main()
