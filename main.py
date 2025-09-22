# data_sheild.py
"""
Data Sheild - Advanced single-file app
Features:
 - Login / Signup with salted password hashing (PBKDF2)
 - Encryption / Decryption (Fernet) with key derived from user's password
 - Load CSV / Excel, preview, basic cleaning
 - Visualization: Histogram, Bar, Line, Pie (Tkinter embedded)
 - Export to CSV / Excel
 - PDF report generation (summary + saved plots)
"""

import os
import json
import base64
import hashlib
import io
from pathlib import Path
from datetime import datetime
from functools import partial

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

import joblib
from PIL import Image, ImageTk

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# ---------------------------
# Config / Paths
# ---------------------------
APP_DIR = Path.home() / ".data_sheild"
APP_DIR.mkdir(exist_ok=True)
USERS_FILE = APP_DIR / "users.json"
SAVED_KEYS_DIR = APP_DIR / "keys"
SAVED_KEYS_DIR.mkdir(exist_ok=True)

# ---------------------------
# Utilities: Password & Key
# ---------------------------
def ensure_users_file():
    if not USERS_FILE.exists():
        with open(USERS_FILE, "w") as f:
            json.dump({}, f)

def generate_salt() -> bytes:
    return os.urandom(16)

def hash_password(password: str, salt: bytes, iterations: int = 200_000) -> str:
    # returns hex representation
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return dk.hex()

def derive_fernet_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    # Use PBKDF2HMAC to generate 32 bytes then base64-urlsafe encode for Fernet
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def load_users():
    ensure_users_file()
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ---------------------------
# Encryption helpers
# ---------------------------
def encrypt_file_bytes(data_bytes: bytes, password: str, salt: bytes) -> bytes:
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    return f.encrypt(data_bytes)

def decrypt_file_bytes(token_bytes: bytes, password: str, salt: bytes) -> bytes:
    key = derive_fernet_key(password, salt)
    f = Fernet(key)
    return f.decrypt(token_bytes)

# ---------------------------
# App GUI
# ---------------------------
class DataSheildApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Data Sheild - Secure Data & Visualization")
        self.root.geometry("1100x700")
        self.root.minsize(900, 600)
        # State
        self.current_user = None
        self.current_user_salt = None
        self.loaded_df = None
        self.loaded_path = None
        self.cleaned_df = None
        self.last_plots = []  # list of saved plot paths
        # Build UI
        self._build_login_frame()

    # ---------------------------
    # Login / Signup
    # ---------------------------
    def _build_login_frame(self):
        self.clear_root()
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(frame, text="Data Sheild", font=("Helvetica", 24, "bold"))
        title.pack(pady=(10, 20))

        card = ttk.Frame(frame, padding=20, relief=tk.RIDGE)
        card.pack(pady=10, ipadx=10, ipady=10)

        ttk.Label(card, text="Username:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.login_username = ttk.Entry(card, width=30)
        self.login_username.grid(row=0, column=1, pady=5)

        ttk.Label(card, text="Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.login_password = ttk.Entry(card, width=30, show="*")
        self.login_password.grid(row=1, column=1, pady=5)

        btn_frame = ttk.Frame(card)
        btn_frame.grid(row=2, column=0, columnspan=2, pady=15)

        login_btn = ttk.Button(btn_frame, text="Login", command=self.login_action)
        login_btn.grid(row=0, column=0, padx=5)
        signup_btn = ttk.Button(btn_frame, text="Sign Up", command=self.signup_action)
        signup_btn.grid(row=0, column=1, padx=5)
        reset_btn = ttk.Button(btn_frame, text="Reset Password", command=self.reset_password_action)
        reset_btn.grid(row=0, column=2, padx=5)

        hint = ttk.Label(frame, text="Your password is used to generate encryption keys — keep it safe.", foreground="gray")
        hint.pack(pady=10)

    def login_action(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if not username or not password:
            messagebox.showwarning("Missing", "Enter username and password.")
            return
        users = load_users()
        if username not in users:
            messagebox.showerror("No user", "User not found. Please sign up.")
            return
        user_rec = users[username]
        salt = bytes.fromhex(user_rec["salt"])
        hashed = hash_password(password, salt)
        if hashed != user_rec["pw_hash"]:
            messagebox.showerror("Wrong", "Incorrect password.")
            return
        # login success
        self.current_user = username
        self.current_user_salt = salt
        messagebox.showinfo("Welcome", f"Welcome back, {username}!")
        self._build_main_ui()

    def signup_action(self):
        username = self.login_username.get().strip()
        password = self.login_password.get().strip()
        if not username or not password:
            messagebox.showwarning("Missing", "Enter username and password to sign up.")
            return
        users = load_users()
        if username in users:
            messagebox.showerror("Exists", "Username already exists. Choose another.")
            return
        salt = generate_salt()
        pw_hash = hash_password(password, salt)
        users[username] = {"salt": salt.hex(), "pw_hash": pw_hash}
        save_users(users)
        messagebox.showinfo("Done", "Sign up complete. Now login with your credentials.")

    def reset_password_action(self):
        # Simple password reset: user must exist and confirm old password then set new password.
        def do_reset():
            uname = uentry.get().strip()
            old = old_entry.get().strip()
            new = new_entry.get().strip()
            if not (uname and old and new):
                messagebox.showwarning("Missing", "Fill all fields.")
                return
            users = load_users()
            if uname not in users:
                messagebox.showerror("No user", "User not found.")
                return
            salt = bytes.fromhex(users[uname]["salt"])
            if hash_password(old, salt) != users[uname]["pw_hash"]:
                messagebox.showerror("Wrong", "Old password incorrect.")
                return
            new_salt = generate_salt()
            users[uname]["salt"] = new_salt.hex()
            users[uname]["pw_hash"] = hash_password(new, new_salt)
            save_users(users)
            messagebox.showinfo("Reset", "Password reset successful.")
            rsw.destroy()

        rsw = tk.Toplevel(self.root)
        rsw.title("Reset Password")
        rsw.geometry("380x220")
        ttk.Label(rsw, text="Username").pack(pady=5)
        uentry = ttk.Entry(rsw); uentry.pack(pady=5)
        ttk.Label(rsw, text="Old Password").pack(pady=5)
        old_entry = ttk.Entry(rsw, show="*"); old_entry.pack(pady=5)
        ttk.Label(rsw, text="New Password").pack(pady=5)
        new_entry = ttk.Entry(rsw, show="*"); new_entry.pack(pady=5)
        ttk.Button(rsw, text="Reset", command=do_reset).pack(pady=10)

    # ---------------------------
    # Main UI
    # ---------------------------
    def _build_main_ui(self):
        self.clear_root()
        # Top menu
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Load File", command=self.load_file)
        file_menu.add_command(label="Export Cleaned CSV", command=self.export_csv, state="normal")
        file_menu.add_command(label="Export Cleaned Excel", command=self.export_excel, state="normal")
        file_menu.add_separator()
        file_menu.add_command(label="Sign Out", command=self.sign_out)
        menubar.add_cascade(label="File", menu=file_menu)

        security_menu = tk.Menu(menubar, tearoff=0)
        security_menu.add_command(label="Encrypt Current File", command=self.encrypt_current_file)
        security_menu.add_command(label="Decrypt File", command=self.decrypt_file_dialog)
        menubar.add_cascade(label="Security", menu=security_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Generate PDF Report", command=self.generate_pdf_report)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        self.root.config(menu=menubar)

        # Main frames
        top_frame = ttk.Frame(self.root, padding=8)
        top_frame.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top_frame, text=f"User: {self.current_user}", font=("Helvetica", 10, "bold")).pack(side=tk.LEFT)

        btns = ttk.Frame(top_frame)
        btns.pack(side=tk.RIGHT)
        ttk.Button(btns, text="Load File", command=self.load_file).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Preview", command=self.preview_data).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Clean Data", command=self.clean_data_dialog).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Visualize", command=self.visualize_dialog).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Export Excel", command=self.export_excel).pack(side=tk.LEFT, padx=4)

        # center: data table preview
        center = ttk.Frame(self.root)
        center.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Treeview for preview
        self.tree = None
        self._build_treeview(center)

        # status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

    def _build_treeview(self, parent):
        if self.tree:
            self.tree.destroy()
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True)
        cols = ("No data loaded",)
        self.tree = ttk.Treeview(frame, columns=cols, show="headings")
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscroll=scrollbar.set)

    def clear_root(self):
        for w in self.root.winfo_children():
            w.destroy()

    def sign_out(self):
        self.current_user = None
        self.current_user_salt = None
        self.loaded_df = None
        self.cleaned_df = None
        self.loaded_path = None
        self.last_plots = []
        self._build_login_frame()

    # ---------------------------
    # File load / preview / export
    # ---------------------------
    def load_file(self):
        fpath = filedialog.askopenfilename(title="Select CSV / Excel / Encrypted file",
                                           filetypes=[("CSV files","*.csv"),("Excel files","*.xlsx *.xls"),("Encrypted","*.enc"),("All","*.*")])
        if not fpath:
            return
        try:
            if fpath.lower().endswith(".enc"):
                # encrypted file, require password to decrypt (we will use current user's password)
                if not self.current_user:
                    messagebox.showerror("Login required", "Please login to decrypt files.")
                    return
                pwd = self.simple_password_prompt("Enter password to decrypt file")
                if pwd is None:
                    return
                # read bytes and decrypt
                with open(fpath, "rb") as f:
                    token = f.read()
                try:
                    plain = decrypt_file_bytes(token, pwd, self.current_user_salt)
                except Exception as e:
                    messagebox.showerror("Decrypt failed", f"Could not decrypt file: {e}")
                    return
                # we have plaintext bytes; write to a BytesIO and load into pandas
                bio = io.BytesIO(plain)
                # guess CSV vs Excel by saved metadata? We will attempt CSV then Excel
                try:
                    df = pd.read_csv(bio)
                except Exception:
                    bio.seek(0)
                    df = pd.read_excel(bio)
                self.loaded_df = df
                self.loaded_path = fpath
                self.cleaned_df = None
                self.status_var.set(f"Loaded (decrypted): {os.path.basename(fpath)}")
                self.display_df_in_tree(df.head(200))
            else:
                if fpath.lower().endswith(".csv"):
                    df = pd.read_csv(fpath)
                else:
                    df = pd.read_excel(fpath)
                self.loaded_df = df
                self.loaded_path = fpath
                self.cleaned_df = None
                self.status_var.set(f"Loaded: {os.path.basename(fpath)}")
                self.display_df_in_tree(df.head(200))
        except Exception as e:
            messagebox.showerror("Load error", f"Failed to load file: {e}")

    def display_df_in_tree(self, df: pd.DataFrame):
        # Clear and populate treeview with dataframe columns and first rows
        for w in self.tree.get_children():
            self.tree.delete(w)
        self.tree["columns"] = list(df.columns)
        self.tree["show"] = "headings"
        for col in df.columns:
            self.tree.heading(col, text=str(col))
            self.tree.column(col, width=120, anchor=tk.W)
        # insert first N rows
        n = min(len(df), 200)
        for i in range(n):
            row = df.iloc[i].astype(str).tolist()
            self.tree.insert("", "end", values=row)

    def preview_data(self):
        if self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first.")
            return
        # Show DataFrame head in a popup with basic stats
        top = tk.Toplevel(self.root)
        top.title("Data Preview & Summary")
        top.geometry("900x600")
        txt = tk.Text(top)
        txt.pack(fill=tk.BOTH, expand=True)
        txt.insert(tk.END, "Preview (first 10 rows):\n\n")
        txt.insert(tk.END, self.loaded_df.head(10).to_string())
        txt.insert(tk.END, "\n\n\nInfo and Summary:\n\n")
        buf = io.StringIO()
        self.loaded_df.info(buf=buf)
        txt.insert(tk.END, buf.getvalue())
        txt.insert(tk.END, "\n\nDescribe (numeric):\n")
        txt.insert(tk.END, str(self.loaded_df.describe(include=[np.number]).transpose()))
        txt.config(state=tk.DISABLED)

    def export_csv(self):
        if self.cleaned_df is None and self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first.")
            return
        df = self.cleaned_df if self.cleaned_df is not None else self.loaded_df
        f = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not f: return
        try:
            df.to_csv(f, index=False)
            messagebox.showinfo("Saved", f"Saved CSV to {f}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def export_excel(self):
        if self.cleaned_df is None and self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first.")
            return
        df = self.cleaned_df if self.cleaned_df is not None else self.loaded_df
        f = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel","*.xlsx")])
        if not f: return
        try:
            df.to_excel(f, index=False)
            messagebox.showinfo("Saved", f"Saved Excel to {f}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    # ---------------------------
    # Cleaning
    # ---------------------------
    def clean_data_dialog(self):
        if self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first.")
            return
        dlg = tk.Toplevel(self.root)
        dlg.title("Data Cleaning Options")
        dlg.geometry("420x320")
        # Options: drop duplicates, drop na, fill na (method), convert types
        var_dropdup = tk.BooleanVar(value=False)
        var_dropna = tk.BooleanVar(value=False)
        var_fillna = tk.BooleanVar(value=False)
        fill_value = tk.StringVar(value="")
        ttk.Checkbutton(dlg, text="Drop Duplicates", variable=var_dropdup).pack(anchor=tk.W, padx=10, pady=6)
        ttk.Checkbutton(dlg, text="Drop rows with any NA", variable=var_dropna).pack(anchor=tk.W, padx=10, pady=6)
        ttk.Checkbutton(dlg, text="Fill missing values (with value)", variable=var_fillna).pack(anchor=tk.W, padx=10, pady=6)
        ttk.Entry(dlg, textvariable=fill_value).pack(fill=tk.X, padx=10, pady=6)
        ttk.Label(dlg, text="Column to convert type (name) and target type (e.g., float, int, str)").pack(anchor=tk.W, padx=10, pady=(8,0))
        conv_col = ttk.Entry(dlg); conv_col.pack(fill=tk.X, padx=10, pady=4)
        conv_type = ttk.Entry(dlg); conv_type.pack(fill=tk.X, padx=10, pady=4)

        def run_clean():
            df = self.loaded_df.copy()
            if var_dropdup.get():
                df = df.drop_duplicates()
            if var_dropna.get():
                df = df.dropna(how="any")
            if var_fillna.get():
                val = fill_value.get()
                # try to parse numeric
                try:
                    jj = float(val)
                except:
                    jj = val
                df = df.fillna(jj)
            ccol = conv_col.get().strip()
            ctype = conv_type.get().strip()
            if ccol and ctype:
                try:
                    if ctype.lower() in ("int","int64"):
                        df[ccol] = df[ccol].astype("Int64")
                    elif ctype.lower() in ("float","float64"):
                        df[ccol] = df[ccol].astype(float)
                    else:
                        df[ccol] = df[ccol].astype(str)
                except Exception as e:
                    messagebox.showwarning("Convert fail", f"Could not convert column: {e}")
            self.cleaned_df = df
            self.display_df_in_tree(df.head(200))
            self.status_var.set("Data cleaned (preview).")
            dlg.destroy()

        ttk.Button(dlg, text="Run Cleaning", command=run_clean).pack(pady=12)

    # ---------------------------
    # Visualization
    # ---------------------------
    def visualize_dialog(self):
        if self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first.")
            return
        dlg = tk.Toplevel(self.root)
        dlg.title("Visualize Data")
        dlg.geometry("440x360")

        df = self.cleaned_df if self.cleaned_df is not None else self.loaded_df

        ttk.Label(dlg, text="Select column (for charts)").pack(anchor=tk.W, padx=10, pady=6)
        colbox = ttk.Combobox(dlg, values=list(df.columns), state="readonly")
        colbox.pack(fill=tk.X, padx=10, pady=6)
        ttk.Label(dlg, text="Select chart type").pack(anchor=tk.W, padx=10, pady=6)
        chart_type = ttk.Combobox(dlg, values=["Histogram","Bar","Line","Pie"], state="readonly")
        chart_type.pack(fill=tk.X, padx=10, pady=6)

        bins_var = tk.IntVar(value=10)
        ttk.Label(dlg, text="Bins (for histogram)").pack(anchor=tk.W, padx=10, pady=4)
        ttk.Entry(dlg, textvariable=bins_var).pack(fill=tk.X, padx=10, pady=4)

        def plot_action():
            col = colbox.get()
            ctype = chart_type.get()
            if not col or not ctype:
                messagebox.showwarning("Missing", "Select column and chart type.")
                return
            self.create_plot(df, col, ctype, bins=bins_var.get())
            dlg.destroy()

        ttk.Button(dlg, text="Plot", command=plot_action).pack(pady=10)

    def create_plot(self, df, column, chart_type, bins=10):
        plt.close("all")
        fig = plt.figure(figsize=(6,4))
        ax = fig.add_subplot(111)
        data = df[column].dropna()

        try:
            if chart_type == "Histogram":
                ax.hist(pd.to_numeric(data, errors='coerce').dropna(), bins=bins)
                ax.set_title(f"Histogram: {column}")
            elif chart_type == "Bar":
                vc = data.astype(str).value_counts().nlargest(20)
                ax.bar(vc.index.astype(str), vc.values)
                ax.set_xticklabels(vc.index.astype(str), rotation=45, ha="right")
                ax.set_title(f"Bar (top 20): {column}")
            elif chart_type == "Line":
                y = pd.to_numeric(data, errors='coerce').dropna().reset_index(drop=True)
                ax.plot(y.index, y.values)
                ax.set_title(f"Line: {column}")
            elif chart_type == "Pie":
                vc = data.astype(str).value_counts().nlargest(10)
                ax.pie(vc.values, labels=vc.index.astype(str), autopct="%1.1f%%")
                ax.set_title(f"Pie (top 10): {column}")
            else:
                messagebox.showwarning("Unknown", "Unknown chart type")
                return
        except Exception as e:
            messagebox.showerror("Plot error", f"Could not create plot: {e}")
            return

        # Save plot to temp file for PDF later
        plot_dir = APP_DIR / "plots"
        plot_dir.mkdir(exist_ok=True)
        fname = plot_dir / f"plot_{datetime.now().strftime('%Y%m%d%H%M%S%f')}.png"
        fig.tight_layout()
        fig.savefig(fname, dpi=150)
        self.last_plots.append(str(fname))

        # Display in Tkinter window
        self.show_plot_in_tk(fig, title=f"{chart_type}: {column}")

    def show_plot_in_tk(self, fig, title="Plot"):
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        top = tk.Toplevel(self.root)
        top.title(title)
        canvas = FigureCanvasTkAgg(fig, master=top)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        toolbar_frame = ttk.Frame(top)
        toolbar_frame.pack()
        ttk.Button(toolbar_frame, text="Save Plot", command=lambda: self.save_plot_dialog(fig)).pack(side=tk.LEFT, padx=5)

    def save_plot_dialog(self, fig):
        f = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG","*.png"),("All","*.*")])
        if not f: return
        fig.savefig(f)
        messagebox.showinfo("Saved", f"Plot saved to {f}")

    # ---------------------------
    # Encryption / Decryption actions
    # ---------------------------
    def simple_password_prompt(self, prompt="Enter password"):
        dlg = tk.Toplevel(self.root)
        dlg.title("Password required")
        dlg.geometry("350x140")
        ttk.Label(dlg, text=prompt).pack(pady=8)
        entry = ttk.Entry(dlg, show="*"); entry.pack(pady=6, padx=10, fill=tk.X)
        result = {"pwd": None}
        def ok():
            result["pwd"] = entry.get()
            dlg.destroy()
        ttk.Button(dlg, text="OK", command=ok).pack(pady=6)
        dlg.transient(self.root)
        dlg.grab_set()
        self.root.wait_window(dlg)
        return result["pwd"]

    def encrypt_current_file(self):
        if self.loaded_df is None or self.loaded_path is None:
            messagebox.showwarning("No file", "Load a file first to encrypt.")
            return
        if not self.current_user:
            messagebox.showwarning("Login", "Please login to encrypt files.")
            return
        pwd = self.simple_password_prompt("Enter your password to encrypt the data (same as login)")
        if pwd is None:
            return
        # Derive bytes of current dataframe
        ext = ".csv" if str(self.loaded_path).lower().endswith(".csv") else ".xlsx"
        # Convert df to bytes
        try:
            if ext == ".csv":
                data = self.loaded_df.to_csv(index=False).encode()
            else:
                bio = io.BytesIO()
                self.loaded_df.to_excel(bio, index=False)
                data = bio.getvalue()
        except Exception as e:
            messagebox.showerror("Pack error", f"Could not serialize data: {e}")
            return
        # Use user's salt to create fernet key
        salt = self.current_user_salt
        try:
            token = encrypt_file_bytes(data, pwd, salt)
        except Exception as e:
            messagebox.showerror("Encrypt fail", f"Encryption failed: {e}")
            return
        # Save token to file
        out = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted","*.enc")])
        if not out:
            return
        with open(out, "wb") as f:
            f.write(token)
        messagebox.showinfo("Encrypted", f"Encrypted file saved to {out}")

    def decrypt_file_dialog(self):
        fpath = filedialog.askopenfilename(title="Select encrypted (.enc) file", filetypes=[("Encrypted","*.enc")])
        if not fpath:
            return
        if not self.current_user:
            messagebox.showwarning("Login", "Please login to decrypt files.")
            return
        pwd = self.simple_password_prompt("Enter your password to decrypt the file")
        if pwd is None:
            return
        try:
            with open(fpath, "rb") as f:
                token = f.read()
            plain = decrypt_file_bytes(token, pwd, self.current_user_salt)
            # ask where to save plaintext file (csv/xlsx)
            out = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv"),("Excel","*.xlsx")])
            if not out:
                return
            # determine CSV vs Excel by extension
            if out.lower().endswith(".csv"):
                # if plain bytes represent excel, reading/writing can be tricky; try detect by reading into pandas
                try:
                    # try decode as text
                    text = plain.decode()
                    with open(out, "w", encoding="utf-8") as of:
                        of.write(text)
                except Exception:
                    # if not text, write bytes directly
                    with open(out, "wb") as of:
                        of.write(plain)
                messagebox.showinfo("Saved", f"Decrypted to {out}")
            else:
                # .xlsx
                with open(out, "wb") as of:
                    of.write(plain)
                messagebox.showinfo("Saved", f"Decrypted to {out}")
        except Exception as e:
            messagebox.showerror("Decrypt error", f"Failed to decrypt: {e}")

    # ---------------------------
    # PDF Report
    # ---------------------------
    def generate_pdf_report(self):
        if self.loaded_df is None:
            messagebox.showwarning("No data", "Load a dataset first to generate a report.")
            return
        df = self.cleaned_df if self.cleaned_df is not None else self.loaded_df
        out = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF","*.pdf")])
        if not out:
            return
        try:
            self._create_pdf_report(df, out)
            messagebox.showinfo("Report", f"Report saved to {out}")
        except Exception as e:
            messagebox.showerror("PDF error", f"Could not create PDF: {e}")

    def _create_pdf_report(self, df: pd.DataFrame, out_pdf_path: str):
        c = canvas.Canvas(out_pdf_path, pagesize=A4)
        width, height = A4
        margin = 40
        y = height - margin
        c.setFont("Helvetica-Bold", 16)
        c.drawString(margin, y, "Data Sheild - Dataset Report")
        c.setFont("Helvetica", 10)
        c.drawString(margin, y-18, f"User: {self.current_user}    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y -= 40

        # Basic info
        c.setFont("Helvetica-Bold", 12)
        c.drawString(margin, y, "Dataset Summary")
        y -= 16
        c.setFont("Helvetica", 9)
        c.drawString(margin, y, f"Rows: {len(df)}    Columns: {len(df.columns)}")
        y -= 14
        c.drawString(margin, y, f"Columns: {', '.join([str(c) for c in df.columns[:10]])}{'...' if len(df.columns)>10 else ''}")
        y -= 20

        # Add describe table (numeric)
        try:
            desc = df.describe(include=[np.number]).transpose().reset_index()
            # We'll write the top 6 numeric columns
            rows = min(8, len(desc))
            c.setFont("Helvetica-Bold", 11)
            c.drawString(margin, y, "Numeric summary (top columns):")
            y -= 14
            c.setFont("Helvetica", 8)
            for i in range(rows):
                r = desc.iloc[i]
                line = f"{r['index']}: count={int(r['count'])}, mean={r['mean']:.3f}, std={r['std']:.3f}, min={r['min']}, max={r['max']}"
                c.drawString(margin, y, line)
                y -= 12
                if y < margin + 120:
                    c.showPage()
                    y = height - margin
        except Exception:
            pass

        # Insert recent plots (last_plots)
        if self.last_plots:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(margin, y, "Charts")
            y -= 18
            for p in self.last_plots[-6:]:
                try:
                    img = Image.open(p)
                    # Resize to fit width
                    maxw = width - 2*margin
                    aspect = img.height / img.width
                    draww = maxw
                    drawh = draww * aspect
                    if y - drawh < margin:
                        c.showPage()
                        y = height - margin
                    c.drawImage(ImageReader(img), margin, y-drawh, width=draww, height=drawh)
                    y -= (drawh + 12)
                except Exception:
                    continue

        c.showPage()
        c.save()

# -----------
# Main
# -----------
def main():
    root = tk.Tk()
    style = ttk.Style(root)
    # Use default theme; style tweaks could be added
    app = DataSheildApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
