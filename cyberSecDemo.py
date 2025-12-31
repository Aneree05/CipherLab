#!/usr/bin/env python3
"""
Simple Tool for Playfair + DES
- Two tabs: Playfair, DES
- Encrypt / Decrypt
- Load ciphertext from file
- Attack :Hil Clim attack/brute force/crib matching

Dependencies:
    pip install pycryptodome
"""

import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
from typing import List, Optional
import random
import math
import time

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad as pkcs7_pad, unpad as pkcs7_unpad

#  Core helpers to clean the texts for us
def _alpha_upper_noj(s: str) -> str:
    return "".join(c for c in s.upper() if c.isalpha()).replace("J", "I")

def _looks_like_hex(s: str) -> bool:
    s = s.strip().replace(" ", "")
    return len(s) > 0 and len(s) % 2 == 0 and all(ch in "0123456789abcdefABCDEF" for ch in s)

def read_text_file() -> Optional[str]:
    path = filedialog.askopenfilename(
        title="Open text file",
        filetypes=[("Text files", "*.txt *.log *.hex *.dat *.cfg *.json *.md"), ("All files", "*.*")]
    )
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return None

# Playfair
def generate_playfair_key_matrix(key: str):
    key = _alpha_upper_noj(key)
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    seen = []
    for c in key + alphabet:
        if c not in seen:
            seen.append(c)
    return [seen[i:i+5] for i in range(0, 25, 5)]

def find_position(matrix, letter):
    letter = "I" if letter.upper() == "J" else letter.upper()
    for r, row in enumerate(matrix):
        if letter in row:
            return r, row.index(letter)
    raise ValueError(f"{letter} not in matrix")

def preprocess_playfair_plaintext(pt: str) -> List[str]:
    s = _alpha_upper_noj(pt)
    out, i = [], 0
    while i < len(s):
        a = s[i]
        b = s[i+1] if i+1 < len(s) else None
        if b is None or a == b:
            out.append(a + "X"); i += 1
        else:
            out.append(a + b); i += 2
    return out

def playfair_encrypt(plaintext: str, key: str) -> str:
    lower = plaintext.islower()
    M = generate_playfair_key_matrix(key)
    out = []
    for a, b in preprocess_playfair_plaintext(plaintext):
        ra, ca = find_position(M, a)
        rb, cb = find_position(M, b)
        if ra == rb:
            out += [M[ra][(ca+1)%5], M[rb][(cb+1)%5]]
        elif ca == cb:
            out += [M[(ra+1)%5][ca], M[(rb+1)%5][cb]]
        else:
            out += [M[ra][cb], M[rb][ca]]
    s = "".join(out)
    return s.lower() if lower else s

def playfair_decrypt(ciphertext: str, key: str, cleanup: bool = True) -> str:
    lower = ciphertext.islower()
    ct = _alpha_upper_noj(ciphertext)
    if len(ct) % 2: ct += "X"
    M = generate_playfair_key_matrix(key)
    out = []
    for i in range(0, len(ct), 2):
        a, b = ct[i], ct[i+1]
        ra, ca = find_position(M, a)
        rb, cb = find_position(M, b)
        if ra == rb:
            out += [M[ra][(ca-1)%5], M[rb][(cb-1)%5]]
        elif ca == cb:
            out += [M[(ra-1)%5][ca], M[(rb-1)%5][cb]]
        else:
            out += [M[ra][cb], M[rb][ca]]
    pt = "".join(out)
    if cleanup:
        cleaned, i = [], 0
        while i < len(pt):
            if i+2 < len(pt) and pt[i] == pt[i+2] and pt[i+1] == "X":
                cleaned.append(pt[i]); i += 2
            else:
                cleaned.append(pt[i]); i += 1
        if cleaned and cleaned[-1] == "X": cleaned.pop()
        pt = "".join(cleaned)
    return pt.lower() if lower else pt

def playfair_try_keys(ciphertext_text: str, keys: List[str], crib: Optional[str] = None) -> List[str]:
    out = []
    for k in keys:
        try:
            pt = playfair_decrypt(ciphertext_text, k)
        except Exception:
            continue
        if not crib or crib.lower() in pt.lower():
            out.append(f"Key: '{k}' -> {pt}")
    return out

#  DES 
def des_encrypt(key_bytes: bytes, plaintext: str) -> bytes:
    if len(key_bytes) != 8: raise ValueError("DES key must be 8 bytes")
    return DES.new(key_bytes, DES.MODE_ECB).encrypt(pkcs7_pad(plaintext.encode("utf-8"), 8))

def des_decrypt(key_bytes: bytes, ciphertext: bytes) -> str:
    if len(key_bytes) != 8: raise ValueError("DES key must be 8 bytes")
    return pkcs7_unpad(DES.new(key_bytes, DES.MODE_ECB).decrypt(ciphertext), 8).decode("utf-8", errors="replace")

def des_try_keys_every(ciphertext: bytes, keys: List[str], crib: Optional[str] = None, preview: int = 60) -> List[str]:
    lines = []
    for k in keys:
        kb = k.encode("utf-8")[:8].ljust(8, b"0")
        kb_hex = kb.hex()
        try:
            pt = des_decrypt(kb, ciphertext)
        except Exception:
            lines.append(f"Key: '{k}' -> normalized: {kb_hex} -> FAILED")
            continue
        short = pt if len(pt) <= preview else pt[:preview] + "..."
        tag = ""
        if crib and crib.strip() and crib.lower() in pt.lower():
            tag = " [CRIB MATCH]"
        lines.append(f"Key: '{k}' -> normalized: {kb_hex} -> SUCCESS: {short}{tag}")
    return lines

#  Hillclimb scoring Parts
# Small quadgram-ish table that help us to make score better(agar andar matching word honge to score badhega)
QUAD_WEIGHT = {
    "TION": 3.4, "THER": 3.2, "HERE": 2.8, "WITH": 2.6, "MENT": 2.5,
    "IONS": 2.4, "ATIO": 2.4, "EVER": 2.0, "THIS": 2.2, "THE ": 4.0
}
COMMON_WORDS = [" the ", " and ", " that ", " to ", " of ", " is ", " in ", " it ", " for ", " you "]

def simple_score_english(s: str) -> float:
    """
    A compact scoring function: mixture of quadgram-ish boosts and common-word counts.
    Higher is better. This is intentionally small and fast for demo purposes.
    """
    if not s:
        return -1e9
    up = s.upper()
    score = 0.0
    # quadgram-ish boosts
    for i in range(len(up) - 3):
        q = up[i:i+4]
        if q in QUAD_WEIGHT:
            score += QUAD_WEIGHT[q]
    # printable ratio + word boosts
    printable = sum(1 for ch in s if 32 <= ord(ch) < 127)
    ratio = printable / max(1, len(s))
    score += ratio * 2.0
    # common word boosts
    low = s.lower()
    for w in COMMON_WORDS:
        if w in low:
            score += 1.0
    # small length normalization (so longer, readable texts win)
    score += math.log(max(1, len(s))) * 0.1
    return score

# Playfair hillclimb helpers 
def keystr_to_matrix(k: str):
    return [list(k[i:i+5]) for i in range(0, 25, 5)]

def matrix_to_keystr(M):
    return "".join("".join(row) for row in M)

def random_key_from_key(key: Optional[str] = None):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    if key:
        # seed with key then remaining letters
        s = _alpha_upper_noj(key)
        seen = []
        for c in s + alphabet:
            if c not in seen:
                seen.append(c)
        k = "".join(seen)
    else:
        lst = list(alphabet)
        random.shuffle(lst)
        k = "".join(lst)
    return k

def playfair_hillclimb(ciphertext: str, restarts: int = 20, iters: int = 2000, seed_key: Optional[str] = None,
                       progress_cb=None, stop_event: Optional[threading.Event] = None):
    """
    Hill-climb search for Playfair key. Ye fuction progress_cb(done_iters, total_iters, best_score, best_key, current_key)
    occasionally (if provided). stop_event is a threading jo threadings process ko stop kar dega.Event used to cancel.
    Returns (best_key, best_plain, best_score)
    """
    best_overall_key = None
    best_overall_plain = ""
    best_score = -1e12
    total_iters = restarts * iters
    done = 0

    for r in range(restarts):
        if stop_event and stop_event.is_set():
            break
        # start key: either seeded or random
        cur_key = random_key_from_key(seed_key) if r == 0 and seed_key else random_key_from_key(seed_key)
        cur_plain = playfair_decrypt(ciphertext, cur_key, cleanup=False)
        cur_score = simple_score_english(cur_plain)
        # local greedy hill-climb
        for i in range(iters):
            if stop_event and stop_event.is_set():
                break
            # neighbor: swap two positions
            lst = list(cur_key)
            a, b = random.sample(range(25), 2)
            lst[a], lst[b] = lst[b], lst[a]
            cand_key = "".join(lst)
            try:
                cand_plain = playfair_decrypt(ciphertext, cand_key, cleanup=False)
            except Exception:
                # skip invalid
                continue
            cand_score = simple_score_english(cand_plain)
            if cand_score > cur_score:
                cur_key, cur_score, cur_plain = cand_key, cand_score, cand_plain
            done += 1
            # callback occasionally
            if progress_cb and (done % 25 == 0 or i == iters-1):
                progress_cb(done, total_iters, best_score, best_overall_key, cur_key)
        # end local hill-climb restart
        
        # finalize candidate (sabse acha score wala english text jo samj me aaye)
        final_plain = playfair_decrypt(ciphertext, cur_key, cleanup=True)
        final_score = simple_score_english(final_plain)
        if final_score > best_score:
            best_score = final_score
            best_overall_key = cur_key
            best_overall_plain = final_plain
        # callback at end of restart
        if progress_cb:
            progress_cb(done, total_iters, best_score, best_overall_key, cur_key)
    return best_overall_key, best_overall_plain, best_score

#  GUI 
class App:
    def __init__(self, root: tk.Tk):
        self.root = root

        # ===== Pastel UI Theme =====
        root.configure(bg="#f8fafc")

        style = ttk.Style()
        style.theme_use("clam")

        style.configure(".", background="#f8fafc", foreground="#0f172a", font=("Segoe UI", 10))

        style.configure("TFrame", background="#f8fafc")
        style.configure("TLabelframe", background="#ffffff", foreground="#2563eb")
        style.configure("TLabelframe.Label", background="#ffffff", foreground="#2563eb",
                        font=("Segoe UI", 11, "bold"))

        style.configure("TLabel", background="#f8fafc", foreground="#0f172a")

        style.configure("TButton",
                        background="#e0e7ff",
                        foreground="#1e3a8a",
                        font=("Segoe UI", 10, "bold"),
                        padding=6)
        style.map("TButton", background=[("active", "#c7d2fe")])

        style.configure("TNotebook", background="#f8fafc")
        style.configure("TNotebook.Tab",
                        background="#dbeafe",
                        foreground="#1e3a8a",
                        font=("Segoe UI", 10, "bold"),
                        padding=(12, 6))
        style.map("TNotebook.Tab", background=[("selected", "#bfdbfe")])

        style.configure("Horizontal.TProgressbar",
                        troughcolor="#e0f2fe",
                        background="#60a5fa",
                        thickness=14)

        # ===== Window =====
        root.title("CipherLab — Playfair & DES Toolkit")
        root.geometry("980x760")

        # Thread control for hillclimb
        self._hill_stop_event = None
        self._hill_thread = None

        # Top bar with global Clear All
        top = ttk.Frame(root)
        top.pack(fill="x", padx=10, pady=(10, 0))
        ttk.Label(top, text="Simple Cipher GUI", font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Button(top, text="Clear All", command=self.clear_all).pack(side="right")

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_pf = ttk.Frame(nb); nb.add(self.tab_pf, text="Playfair")
        self.tab_des = ttk.Frame(nb); nb.add(self.tab_des, text="DES")

        self.build_playfair()
        self.build_des()

    # ----- Everything below remains unchanged from your original -----

    def build_playfair(self):
        left = ttk.LabelFrame(self.tab_pf, text="Encrypt / Decrypt", padding=8)
        left.pack(side="left", fill="both", expand=True, padx=(0,5), pady=5)

        row_k = ttk.Frame(left); row_k.pack(fill="x", pady=2)
        ttk.Label(row_k, text="Key:").pack(side="left")
        self.pf_key = ttk.Entry(row_k); self.pf_key.pack(side="left", fill="x", expand=True, padx=6)

        row_pt = ttk.Frame(left); row_pt.pack(fill="x", pady=(6,2))
        ttk.Label(row_pt, text="Plaintext:").pack(side="left")
        ttk.Button(row_pt, text="Clear", width=8, command=lambda: self.clear_text(self.pf_pt)).pack(side="right")
        self.pf_pt = ScrolledText(left, height=7, wrap="word"); self.pf_pt.pack(fill="both", expand=True)

        row_ct = ttk.Frame(left); row_ct.pack(fill="x", pady=(6,2))
        ttk.Label(row_ct, text="Ciphertext:").pack(side="left")
        ttk.Button(row_ct, text="Clear", width=8, command=lambda: self.clear_text(self.pf_ct)).pack(side="right")
        self.pf_ct = ScrolledText(left, height=7, wrap="word"); self.pf_ct.pack(fill="both", expand=True)

        row_btn = ttk.Frame(left); row_btn.pack(fill="x", pady=6)
        ttk.Button(row_btn, text="Encrypt →", command=self.pf_encrypt).pack(side="left")
        ttk.Button(row_btn, text="← Decrypt", command=self.pf_decrypt).pack(side="left", padx=6)
        ttk.Button(row_btn, text="Load CT From File", command=self.pf_load_ct_file).pack(side="right")

        right = ttk.LabelFrame(self.tab_pf, text="Attack (Try Keys)", padding=8)
        right.pack(side="left", fill="both", expand=True, padx=(5,0), pady=5)

        row_act = ttk.Frame(right); row_act.pack(fill="x", pady=(2,2))
        ttk.Label(row_act, text="Ciphertext (used for attack):").pack(side="left")
        ttk.Button(row_act, text="Clear", width=8, command=lambda: self.clear_text(self.pf_attack_ct)).pack(side="right")
        self.pf_attack_ct = ScrolledText(right, height=5, wrap="word"); self.pf_attack_ct.pack(fill="both", expand=True)

        row_keys = ttk.Frame(right); row_keys.pack(fill="x", pady=(6,2))
        ttk.Label(row_keys, text="Keys (one per line):").pack(side="left")
        ttk.Button(row_keys, text="Clear", width=8, command=lambda: self.clear_text(self.pf_keys)).pack(side="right")
        self.pf_keys = ScrolledText(right, height=6, wrap="word"); self.pf_keys.pack(fill="both", expand=True)

        row_crib = ttk.Frame(right); row_crib.pack(fill="x", pady=6)
        ttk.Label(row_crib, text="Optional crib:").pack(side="left")
        self.pf_crib = ttk.Entry(row_crib); self.pf_crib.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(row_crib, text="Load CT From File", command=self.pf_load_ct_attack).pack(side="right")
        ttk.Button(row_crib, text="Load Keys From File", command=self.pf_load_keys_attack).pack(side="right", padx=6)

        btn_row = ttk.Frame(right); btn_row.pack(fill="x", pady=6)
        ttk.Button(btn_row, text="Run Attack", command=self.pf_attack_thread).pack(side="left")
        ttk.Button(btn_row, text="Hillclimb Attack", command=self.pf_hillclimb_thread).pack(side="left", padx=6)
        self.pf_hill_cancel_btn = ttk.Button(btn_row, text="Cancel Hillclimb", command=self.pf_hill_cancel)
        self.pf_hill_cancel_btn.pack(side="left", padx=6)
        self.pf_hill_cancel_btn["state"] = "disabled"

        params_row = ttk.Frame(right); params_row.pack(fill="x", pady=4)
        ttk.Label(params_row, text="Restarts:").pack(side="left")
        self.pf_restarts = ttk.Entry(params_row, width=6); self.pf_restarts.pack(side="left", padx=4)
        self.pf_restarts.insert(0, "16")
        ttk.Label(params_row, text="Iters:").pack(side="left", padx=(8,0))
        self.pf_iters = ttk.Entry(params_row, width=8); self.pf_iters.pack(side="left", padx=4)
        self.pf_iters.insert(0, "1200")
        ttk.Label(params_row, text="Preview top (chars):").pack(side="left", padx=(8,0))
        self.pf_preview = ttk.Entry(params_row, width=6); self.pf_preview.pack(side="left", padx=4)
        self.pf_preview.insert(0, "180")

        progress_row = ttk.Frame(right); progress_row.pack(fill="x", pady=4)
        self.pf_progress = ttk.Progressbar(progress_row, orient="horizontal", mode="determinate")
        self.pf_progress.pack(fill="x", side="left", expand=True, padx=(0,6))
        self.pf_best_label = ttk.Label(progress_row, text="Best: -")
        self.pf_best_label.pack(side="right")

        row_out = ttk.Frame(right); row_out.pack(fill="x", pady=(6,2))
        ttk.Label(row_out, text="Attack Output:").pack(side="left")
        ttk.Button(row_out, text="Clear", width=8, command=lambda: self.clear_text(self.pf_attack_out)).pack(side="right")
        self.pf_attack_out = ScrolledText(right, height=7, wrap="word"); self.pf_attack_out.pack(fill="both", expand=True)

    def build_des(self):
        left = ttk.LabelFrame(self.tab_des, text="Encrypt / Decrypt", padding=8)
        left.pack(side="left", fill="both", expand=True, padx=(0,5), pady=5)

        row_k = ttk.Frame(left); row_k.pack(fill="x", pady=2)
        ttk.Label(row_k, text="Key (text → 8 bytes):").pack(side="left")
        self.des_key = ttk.Entry(row_k); self.des_key.pack(side="left", fill="x", expand=True, padx=6)

        row_pt = ttk.Frame(left); row_pt.pack(fill="x", pady=(6,2))
        ttk.Label(row_pt, text="Plaintext:").pack(side="left")
        ttk.Button(row_pt, text="Clear", width=8, command=lambda: self.clear_text(self.des_pt)).pack(side="right")
        self.des_pt = ScrolledText(left, height=7, wrap="word"); self.des_pt.pack(fill="both", expand=True)

        row_ct = ttk.Frame(left); row_ct.pack(fill="x", pady=(6,2))
        ttk.Label(row_ct, text="Ciphertext (hex):").pack(side="left")
        ttk.Button(row_ct, text="Clear", width=8, command=lambda: self.clear_text(self.des_ct_hex)).pack(side="right")
        self.des_ct_hex = ScrolledText(left, height=7, wrap="word"); self.des_ct_hex.pack(fill="both", expand=True)

        row_btn = ttk.Frame(left); row_btn.pack(fill="x", pady=6)
        ttk.Button(row_btn, text="Encrypt → Hex", command=self.des_encrypt).pack(side="left")
        ttk.Button(row_btn, text="← Decrypt from Hex", command=self.des_decrypt).pack(side="left", padx=6)
        ttk.Button(row_btn, text="Load CT From File", command=self.des_load_ct_file).pack(side="right")

        right = ttk.LabelFrame(self.tab_des, text="Attack (Try Keys)", padding=8)
        right.pack(side="left", fill="both", expand=True, padx=(5,0), pady=5)

        row_act = ttk.Frame(right); row_act.pack(fill="x", pady=(2,2))
        ttk.Label(row_act, text="Ciphertext (hex, used for attack):").pack(side="left")
        ttk.Button(row_act, text="Clear", width=8, command=lambda: self.clear_text(self.des_attack_ct_hex)).pack(side="right")
        self.des_attack_ct_hex = ScrolledText(right, height=5, wrap="word"); self.des_attack_ct_hex.pack(fill="both", expand=True)

        row_keys = ttk.Frame(right); row_keys.pack(fill="x", pady=(6,2))
        ttk.Label(row_keys, text="Keys (one per line):").pack(side="left")
        ttk.Button(row_keys, text="Clear", width=8, command=lambda: self.clear_text(self.des_keys)).pack(side="right")
        self.des_keys = ScrolledText(right, height=6, wrap="word"); self.des_keys.pack(fill="both", expand=True)

        row_crib = ttk.Frame(right); row_crib.pack(fill="x", pady=6)
        ttk.Label(row_crib, text="Optional crib:").pack(side="left")
        self.des_crib = ttk.Entry(row_crib); self.des_crib.pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(row_crib, text="Load CT From File", command=self.des_load_ct_attack).pack(side="right")
        ttk.Button(row_crib, text="Load Keys From File", command=self.des_load_keys_attack).pack(side="right", padx=6)

        ttk.Button(right, text="Run Attack", command=self.des_attack_thread).pack(anchor="e")

        row_out = ttk.Frame(right); row_out.pack(fill="x", pady=(6,2))
        ttk.Label(row_out, text="Attack Output:").pack(side="left")
        ttk.Button(row_out, text="Clear", width=8, command=lambda: self.clear_text(self.des_attack_out)).pack(side="right")
        self.des_attack_out = ScrolledText(right, height=7, wrap="word"); self.des_attack_out.pack(fill="both", expand=True)

    # ---------- Clear helpers ----------
    def clear_text(self, widget: ScrolledText):
        try:
            widget.delete("1.0", "end")
        except Exception:
            pass

    def clear_entry(self, entry: tk.Entry):
        try:
            entry.delete(0, "end")
        except Exception:
            pass

    def clear_all(self):
        # Playfair widgets
        self.clear_entry(self.pf_key)
        self.clear_text(self.pf_pt)
        self.clear_text(self.pf_ct)
        self.clear_text(self.pf_attack_ct)
        self.clear_text(self.pf_keys)
        self.clear_entry(self.pf_crib)
        self.clear_text(self.pf_attack_out)
        # DES widgets
        self.clear_entry(self.des_key)
        self.clear_text(self.des_pt)
        self.clear_text(self.des_ct_hex)
        self.clear_text(self.des_attack_ct_hex)
        self.clear_text(self.des_keys)
        self.clear_entry(self.des_crib)
        self.clear_text(self.des_attack_out)

    # ---------- Playfair ops ----------
    def pf_encrypt(self):
        key = self.pf_key.get().strip()
        if not key: return messagebox.showerror("Error", "Key is required.")
        try:
            ct = playfair_encrypt(self.pf_pt.get("1.0", "end-1c"), key)
            self.pf_ct.delete("1.0", "end"); self.pf_ct.insert("1.0", ct)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def pf_decrypt(self):
        key = self.pf_key.get().strip()
        if not key: return messagebox.showerror("Error", "Key is required.")
        try:
            pt = playfair_decrypt(self.pf_ct.get("1.0", "end-1c"), key)
            self.pf_pt.delete("1.0", "end"); self.pf_pt.insert("1.0", pt)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def pf_load_ct_file(self):
        data = read_text_file()
        if data is not None:
            self.pf_ct.delete("1.0", "end"); self.pf_ct.insert("1.0", _alpha_upper_noj(data))

    def pf_load_ct_attack(self):
        data = read_text_file()
        if data is not None:
            self.pf_attack_ct.delete("1.0", "end"); self.pf_attack_ct.insert("1.0", _alpha_upper_noj(data))

    def pf_load_keys_attack(self):
        data = read_text_file()
        if data is not None:
            self.pf_keys.delete("1.0", "end"); self.pf_keys.insert("1.0", data)

    def pf_attack_thread(self):
        ct = self.pf_attack_ct.get("1.0", "end-1c")
        keys = [k.strip() for k in self.pf_keys.get("1.0", "end-1c").splitlines() if k.strip()]
        crib = self.pf_crib.get().strip()
        if not ct: return messagebox.showerror("Error", "Provide ciphertext for attack.")
        if not keys: return messagebox.showerror("Error", "Provide keys (one per line).")

        self.pf_attack_out.delete("1.0", "end"); self.pf_attack_out.insert("1.0", "Running attack...\n")
        def worker():
            try:
                lines = playfair_try_keys(ct, keys, crib if crib else None) or ["No results."]
            except Exception as e:
                lines = [f"Error: {e}"]
            self.pf_attack_out.delete("1.0", "end"); self.pf_attack_out.insert("1.0", "\n".join(lines))
        threading.Thread(target=worker, daemon=True).start()

    #  Playfair hillclimb UI handlers 
    def pf_hillclimb_thread(self):
        # start hillclimb in background
        if self._hill_thread and self._hill_thread.is_alive():
            messagebox.showinfo("Hillclimb", "Hillclimb already running.")
            return
        ct = self.pf_attack_ct.get("1.0", "end-1c").strip()
        if not ct:
            return messagebox.showerror("Error", "Provide ciphertext for hillclimb attack.")
        try:
            restarts = max(1, int(self.pf_restarts.get().strip()))
        except Exception:
            restarts = 16
        try:
            iters = max(10, int(self.pf_iters.get().strip()))
        except Exception:
            iters = 1200
        preview = int(self.pf_preview.get().strip()) if self.pf_preview.get().strip().isdigit() else 180

        # prepare UI
        self.pf_progress["maximum"] = restarts * iters
        self.pf_progress["value"] = 0
        self.pf_best_label["text"] = "Best: -"
        self.pf_attack_out.delete("1.0", "end")
        self.pf_hill_cancel_btn["state"] = "normal"

        self._hill_stop_event = threading.Event()

        def progress_cb(done, total, best_score, best_key, cur_key):
            # schedule UI update on main thread
            def ui_update():
                self.pf_progress["value"] = done
                if best_key:
                    self.pf_best_label["text"] = f"Best: {best_score:.2f} key={best_key[:8]}..."
                else:
                    self.pf_best_label["text"] = f"Iter: {done}/{total}"
            self.root.after(1, ui_update)

        def worker():
            try:
                seed_key = self.pf_key.get().strip() or None
                best_key, best_plain, best_score = playfair_hillclimb(
                    ct, restarts=restarts, iters=iters, seed_key=seed_key,
                    progress_cb=progress_cb, stop_event=self._hill_stop_event
                )
                # final UI update
                def finish_ui():
                    self.pf_hill_cancel_btn["state"] = "disabled"
                    if not best_key:
                        self.pf_attack_out.insert("1.0", "No promising key found.\n")
                        self.pf_best_label["text"] = "Best: -"
                    else:
                        self.pf_attack_out.insert("1.0", f"Best key: {best_key}\nScore: {best_score:.2f}\n\nPlaintext preview:\n{best_plain[:preview]}\n")
                        self.pf_best_label["text"] = f"Best: {best_score:.2f} key={best_key[:8]}..."
                        # also insert full plaintext below
                        self.pf_attack_out.insert("end", "\nFull plaintext:\n" + best_plain + "\n")
                self.root.after(1, finish_ui)
            except Exception as e:
                def err_ui():
                    messagebox.showerror("Error", f"Hillclimb error: {e}")
                    self.pf_hill_cancel_btn["state"] = "disabled"
                self.root.after(1, err_ui)

        self._hill_thread = threading.Thread(target=worker, daemon=True)
        self._hill_thread.start()

    def pf_hill_cancel(self):
        if self._hill_stop_event:
            self._hill_stop_event.set()
        self.pf_hill_cancel_btn["state"] = "disabled"
        # progress bar will stop updating when worker checks the event

    #  DES ops 
    def des_encrypt(self):
        key = self.des_key.get().strip()
        if not key: return messagebox.showerror("Error", "Key is required.")
        kb = key.encode("utf-8")[:8].ljust(8, b"0")
        try:
            ct = des_encrypt(kb, self.des_pt.get("1.0", "end-1c"))
            self.des_ct_hex.delete("1.0", "end"); self.des_ct_hex.insert("1.0", ct.hex())
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def des_decrypt(self):
        key = self.des_key.get().strip()
        if not key: return messagebox.showerror("Error", "Key is required.")
        ct_hex = self.des_ct_hex.get("1.0", "end-1c").strip().replace(" ", "")
        if not _looks_like_hex(ct_hex): return messagebox.showerror("Error", "Ciphertext must be valid hex.")
        kb = key.encode("utf-8")[:8].ljust(8, b"0")
        try:
            pt = des_decrypt(kb, bytes.fromhex(ct_hex))
            self.des_pt.delete("1.0", "end"); self.des_pt.insert("1.0", pt)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def des_load_ct_file(self):
        data = read_text_file()
        if data is not None:
            raw = data.strip().replace(" ", "")
            if _looks_like_hex(raw):
                self.des_ct_hex.delete("1.0", "end"); self.des_ct_hex.insert("1.0", raw)
            else:
                messagebox.showerror("Error", "File does not contain valid hex ciphertext.")

    def des_load_ct_attack(self):
        data = read_text_file()
        if data is not None:
            raw = data.strip().replace(" ", "")
            if _looks_like_hex(raw):
                self.des_attack_ct_hex.delete("1.0", "end"); self.des_attack_ct_hex.insert("1.0", raw)
            else:
                messagebox.showerror("Error", "File does not contain valid hex ciphertext.")

    def des_load_keys_attack(self):
        data = read_text_file()
        if data is not None:
            self.des_keys.delete("1.0", "end"); self.des_keys.insert("1.0", data)

    def des_attack_thread(self):
        ct_hex = self.des_attack_ct_hex.get("1.0", "end-1c").strip().replace(" ", "")
        keys = [k.strip() for k in self.des_keys.get("1.0", "end-1c").splitlines() if k.strip()]
        crib = self.des_crib.get().strip()

        if not _looks_like_hex(ct_hex):
            return messagebox.showerror("Error", "Provide valid hex ciphertext.")
        if not keys:
            return messagebox.showerror("Error", "Provide keys (one per line).")

        self.des_attack_out.delete("1.0", "end")
        self.des_attack_out.insert("1.0", "Running attack...\n")

        def worker():
            try:
                lines = des_try_keys_every(bytes.fromhex(ct_hex), keys, crib if crib else None) or ["No results."]
            except Exception as e:
                lines = [f"Error: {e}"]
            self.des_attack_out.delete("1.0", "end")
            self.des_attack_out.insert("1.0", "\n".join(lines))

        threading.Thread(target=worker, daemon=True).start()

#  run 
if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
