import os
import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import shutil
import secrets
import threading
import time
from datetime import datetime, timedelta
import json

# Secure notes folder in Documents
DOCUMENTS_DIR = os.path.expanduser("~/Documents")
SECURE_NOTES_DIR = os.path.join(DOCUMENTS_DIR, "SecureNotes")

# Create the directory if it doesn't exist
if not os.path.exists(SECURE_NOTES_DIR):
    os.makedirs(SECURE_NOTES_DIR)

# Define file paths in the secure notes directory
ENC_FILE = os.path.join(SECURE_NOTES_DIR, "notes.secure")
BACKUP_FILE = os.path.join(SECURE_NOTES_DIR, "notes.secure.bak")

# Check if there's an existing notes file in the old location
OLD_ENC_FILE = "notes.secure"
OLD_BACKUP_FILE = "notes.secure.bak"

# Move existing files to the new location if they exist
if os.path.exists(OLD_ENC_FILE) and not os.path.exists(ENC_FILE):
    print(f"Moving existing notes file to {SECURE_NOTES_DIR}")
    shutil.move(OLD_ENC_FILE, ENC_FILE)
    if os.path.exists(OLD_BACKUP_FILE):
        shutil.move(OLD_BACKUP_FILE, BACKUP_FILE)

INACTIVITY_TIMEOUT = 300  # 5 minutes in seconds
WARNING_BEFORE_LOCK = 30  # 30 seconds warning before lock

class SecureStorage:
    def __init__(self, password: str):
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key(password, self.salt)
        self.mac_key = self._derive_mac_key(password, self.salt)
        self.counter = 0

    def _get_or_create_salt(self) -> bytes:
        if os.path.exists(ENC_FILE):
            with open(ENC_FILE, "rb") as f:
                return f.read(16)
        return os.urandom(16)

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=4,
            lanes=2,
            memory_cost=2**16,
        )
        return kdf.derive(password.encode())

    def _derive_mac_key(self, password: str, salt: bytes) -> bytes:
        kdf = Argon2id(
            salt=salt + b"MAC",
            length=32,
            iterations=4,
            lanes=2,
            memory_cost=2**16,
        )
        return kdf.derive(password.encode())

    def _encrypt_data(self, data: bytes, counter: int) -> bytes:
        nonce = counter.to_bytes(8, 'big') + secrets.token_bytes(4)
        aesgcm = AESGCM(self.key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext

    def _decrypt_data(self, blob: bytes) -> bytes:
        nonce = blob[:12]
        ciphertext = blob[12:]
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def _compute_file_mac(self, data: bytes) -> bytes:
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        return h.finalize()

    def _verify_file_mac(self, data: bytes, mac: bytes) -> bool:
        h = hmac.HMAC(self.mac_key, hashes.SHA256(), backend=default_backend())
        h.update(data)
        try:
            h.verify(mac)
            return True
        except:
            return False

    def initialize_file(self):
        if os.path.exists(ENC_FILE):
            return
        
        # Structure: salt + counter + version + notes_data
        notes_data = {"notes": [], "version": 2}  # Version 2 for title/body structure
        encrypted = self._encrypt_data(json.dumps(notes_data).encode("utf-8"), 0)
        content = self.salt + (0).to_bytes(8, 'big') + (2).to_bytes(4, 'big') + encrypted
        mac = self._compute_file_mac(content)
        
        with open(ENC_FILE, "wb") as f:
            f.write(content + mac)

    def load_notes(self) -> tuple[list, int]:
        with open(ENC_FILE, "rb") as f:
            blob = f.read()
        
        mac = blob[-32:]
        content = blob[:-32]
        
        if not self._verify_file_mac(content, mac):
            raise ValueError("File integrity check failed")
        
        salt = content[:16]
        counter = int.from_bytes(content[16:24], 'big')
        version = int.from_bytes(content[24:28], 'big')
        encrypted_data = content[28:]
        
        data = self._decrypt_data(encrypted_data)
        notes_data = json.loads(data.decode("utf-8"))
        
        # Handle version migration
        if version == 1 or notes_data.get("version", 1) == 1:
            # Migrate from version 1 (string notes) to version 2 (title/body)
            old_notes = notes_data.get("notes", [])
            new_notes = []
            for i, note in enumerate(old_notes):
                title = note.split('\n')[0][:50] if note else f"Note {i+1}"
                new_notes.append({"title": title, "body": note})
            notes_data = {"notes": new_notes, "version": 2}
            # Save the migrated data
            self.save_notes(new_notes, counter)
        
        return notes_data.get("notes", []), counter

    def save_notes(self, notes: list, counter: int):
        if os.path.exists(ENC_FILE):
            shutil.copy2(ENC_FILE, BACKUP_FILE)
        
        counter += 1
        
        try:
            notes_data = {"notes": notes, "version": 2}
            encrypted = self._encrypt_data(json.dumps(notes_data).encode("utf-8"), counter)
            content = self.salt + counter.to_bytes(8, 'big') + (2).to_bytes(4, 'big') + encrypted
            mac = self._compute_file_mac(content)
            
            temp_file = ENC_FILE + ".tmp"
            with open(temp_file, "wb") as f:
                f.write(content + mac)
            
            os.replace(temp_file, ENC_FILE)
            
            if os.path.exists(BACKUP_FILE):
                os.remove(BACKUP_FILE)
        except Exception as e:
            if os.path.exists(BACKUP_FILE):
                shutil.copy2(BACKUP_FILE, ENC_FILE)
            raise e

    def clear_keys(self):
        """Zero out sensitive key material"""
        if hasattr(self, 'key'):
            self.key = bytearray(32)
        if hasattr(self, 'mac_key'):
            self.mac_key = bytearray(32)

class LockScreen(tk.Toplevel):
    def __init__(self, parent, on_unlock_callback):
        super().__init__(parent)
        self.parent = parent
        self.on_unlock_callback = on_unlock_callback
        self.title("Secure Notes - Locked")
        self.geometry("400x250")
        self.resizable(False, False)
        
        # Configure window
        self.configure(bg='white')
        
        # Create main frame
        main_frame = tk.Frame(self, bg='white')
        main_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)
        
        # Create UI elements
        tk.Label(main_frame, text="Session Locked", font=("Arial", 18, "bold"), 
                bg='white').pack(pady=(0, 20))
        
        tk.Label(main_frame, text="Enter password to unlock:", font=("Arial", 12), 
                bg='white').pack(pady=(0, 10))
        
        self.password_entry = tk.Entry(main_frame, show="*", width=30, font=("Arial", 12))
        self.password_entry.pack(pady=(0, 20))
        
        button_frame = tk.Frame(main_frame, bg='white')
        button_frame.pack()
        
        unlock_button = tk.Button(button_frame, text="Unlock", command=self.unlock, 
                                width=10, font=("Arial", 12))
        unlock_button.pack(side=tk.LEFT, padx=5)
        
        cancel_button = tk.Button(button_frame, text="Cancel", command=self.cancel, 
                                width=10, font=("Arial", 12))
        cancel_button.pack(side=tk.LEFT, padx=5)
        
        # Bind Enter key
        self.password_entry.bind("<Return>", lambda e: self.unlock())
        
        # Center the window
        self.update_idletasks()
        x = (self.winfo_screenwidth() - self.winfo_width()) // 2
        y = (self.winfo_screenheight() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
        
        # Make this window modal and bring to front
        self.transient(parent)
        self.grab_set()
        self.lift()
        self.focus_force()
        
        # Focus on password entry
        self.password_entry.focus_set()
        
        # Handle window close button
        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def unlock(self):
        password = self.password_entry.get()
        self.password_entry.delete(0, tk.END)
        
        if self.on_unlock_callback(password):
            self.destroy()
        else:
            messagebox.showerror("Error", "Incorrect password", parent=self)
            self.password_entry.focus_set()
    
    def cancel(self):
        # Allow closing the lock screen, which will effectively close the app
        self.parent.quit()
        self.parent.destroy()

class SecureNotesApp:
    def __init__(self, root, storage: SecureStorage):
        self.root = root
        self.root.title("Secure Notes")
        self.storage = storage
        self.notes, self.counter = storage.load_notes()
        
        # Auto-lock variables
        self.last_activity = time.time()
        self.lock_timer = None
        self.warning_dialog = None
        self.is_locked = False
        
        # Search variable
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.filter_notes)
        self.filtered_indices = []
        
        self.create_ui()
        self.refresh_display()
        self.start_activity_monitor()
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Search frame
        search_frame = tk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, width=40)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Listbox with scrollbar
        listbox_frame = tk.Frame(main_frame)
        listbox_frame.pack(fill=tk.BOTH, expand=True)
        
        self.listbox = tk.Listbox(listbox_frame, width=60, height=20)
        self.listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(listbox_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.listbox.yview)
        
        # Keyboard shortcuts for listbox
        self.listbox.bind("<Double-Button-1>", lambda e: self.view_note())
        self.listbox.bind("<Return>", lambda e: self.view_note())
        self.listbox.bind("<Delete>", lambda e: self.delete_note())
        
        # Right-click context menu
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="View", command=self.view_note)
        self.context_menu.add_command(label="Delete", command=self.delete_note)
        
        self.listbox.bind("<Button-3>", self.show_context_menu)
        
        # Button frame
        button_frame = tk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.add_button = tk.Button(button_frame, text="Add Note (Ctrl+N)", command=self.add_note)
        self.add_button.pack(side=tk.LEFT, padx=5)
        
        self.view_button = tk.Button(button_frame, text="View Note", command=self.view_note)
        self.view_button.pack(side=tk.LEFT, padx=5)
        
        self.delete_button = tk.Button(button_frame, text="Delete Note", command=self.delete_note)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        
        self.lock_button = tk.Button(button_frame, text="Lock Vault", command=self.manual_lock)
        self.lock_button.pack(side=tk.LEFT, padx=5)
        
        # Global keyboard shortcuts
        self.root.bind("<Control-n>", lambda e: self.add_note())
        
        # Activity tracking
        self.root.bind("<Button-1>", self.update_activity)
        self.root.bind("<Key>", self.update_activity)
        self.root.bind("<Motion>", self.update_activity)

    def show_context_menu(self, event):
        try:
            self.listbox.selection_clear(0, tk.END)
            self.listbox.selection_set(self.listbox.nearest(event.y))
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def filter_notes(self, *args):
        search_term = self.search_var.get().lower()
        self.filtered_indices = []
        
        for i, note in enumerate(self.notes):
            # Search in both title and body
            title = note.get("title", "").lower()
            body = note.get("body", "").lower()
            if search_term in title or search_term in body:
                self.filtered_indices.append(i)
        
        self.refresh_display()

    def refresh_display(self):
        self.listbox.delete(0, tk.END)
        
        indices_to_show = self.filtered_indices if self.search_var.get() else range(len(self.notes))
        
        for idx in indices_to_show:
            note = self.notes[idx]
            # Show only the title in the list view
            title = note.get("title", f"Note {idx + 1}")
            self.listbox.insert(tk.END, f"{idx + 1}: {title}")

    def get_selected_note_index(self):
        selection = self.listbox.curselection()
        if not selection:
            return None
        
        if self.search_var.get():
            return self.filtered_indices[selection[0]]
        return selection[0]

    def add_note(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("New Note")
        dialog.geometry("600x500")
        
        # Title frame
        title_frame = tk.Frame(dialog)
        title_frame.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(title_frame, text="Title:", font=("Arial", 12)).pack(side=tk.LEFT, padx=(0, 5))
        title_entry = tk.Entry(title_frame, width=50, font=("Arial", 12))
        title_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Body frame
        tk.Label(dialog, text="Note content:", font=("Arial", 12)).pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        text_frame = tk.Frame(dialog)
        text_frame.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, width=60, height=20, font=("Arial", 11))
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)
        
        def save_note():
            title = title_entry.get().strip()
            body = text_widget.get("1.0", tk.END).strip()
            
            if not title:
                messagebox.showwarning("Warning", "Please enter a title for your note.")
                return
            
            if not body:
                messagebox.showwarning("Warning", "Please enter some content for your note.")
                return
            
            try:
                self.notes.append({"title": title, "body": body})
                self.storage.save_notes(self.notes, self.counter)
                self.counter += 1
                self.refresh_display()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save note: {str(e)}")
            dialog.destroy()
        
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Save", command=save_note, width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Cancel", command=dialog.destroy, width=10).pack(side=tk.LEFT, padx=5)
        
        dialog.bind("<Escape>", lambda e: dialog.destroy())
        title_entry.focus()

    def view_note(self):
        index = self.get_selected_note_index()
        if index is None:
            messagebox.showwarning("No selection", "Please select a note to view.")
            return
        
        note = self.notes[index]
        title = note.get("title", f"Note {index + 1}")
        body = note.get("body", "")
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"View: {title}")
        dialog.geometry("600x500")
        
        # Title display
        title_frame = tk.Frame(dialog, bg='#f0f0f0', pady=10)
        title_frame.pack(fill=tk.X)
        
        title_label = tk.Label(title_frame, text=title, font=("Arial", 16, "bold"), 
                              bg='#f0f0f0', wraplength=550)
        title_label.pack(padx=20)
        
        # Separator
        separator = tk.Frame(dialog, height=2, bg='gray')
        separator.pack(fill=tk.X, padx=20, pady=(0, 10))
        
        # Body display
        text_frame = tk.Frame(dialog)
        text_frame.pack(padx=20, pady=10, fill=tk.BOTH, expand=True)
        
        text_widget = tk.Text(text_frame, wrap=tk.WORD, font=("Arial", 11))
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(text_frame, orient=tk.VERTICAL)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        text_widget.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=text_widget.yview)
        
        text_widget.insert("1.0", body)
        text_widget.config(state=tk.DISABLED)
        
        # Disable clipboard operations
        def block_copy(event):
            return "break"
        
        text_widget.bind("<Control-c>", block_copy)
        text_widget.bind("<Command-c>", block_copy)  # macOS
        text_widget.bind("<Button-3>", block_copy)   # Right-click
        
        # Disable text selection
        text_widget.bind("<B1-Motion>", lambda e: "break")
        text_widget.bind("<Double-Button-1>", lambda e: "break")
        text_widget.bind("<Triple-Button-1>", lambda e: "break")
        
        # Close button
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="Close", command=dialog.destroy, width=10).pack()
        
        dialog.bind("<Escape>", lambda e: dialog.destroy())

    def delete_note(self):
        index = self.get_selected_note_index()
        if index is None:
            messagebox.showwarning("No selection", "Please select a note to delete.")
            return
        
        if messagebox.askyesno("Confirm Delete", f"Delete note {index + 1}?"):
            try:
                del self.notes[index]
                self.storage.save_notes(self.notes, self.counter)
                self.counter += 1
                self.refresh_display()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete note: {str(e)}")

    def update_activity(self, event=None):
        self.last_activity = time.time()
        if self.warning_dialog:
            self.warning_dialog.destroy()
            self.warning_dialog = None
            self.start_activity_monitor()

    def start_activity_monitor(self):
        if self.lock_timer:
            self.root.after_cancel(self.lock_timer)
        
        def check_activity():
            if self.is_locked:
                return
            
            idle_time = time.time() - self.last_activity
            
            if idle_time >= INACTIVITY_TIMEOUT:
                self.auto_lock()
            elif idle_time >= INACTIVITY_TIMEOUT - WARNING_BEFORE_LOCK and not self.warning_dialog:
                self.show_lock_warning()
            else:
                self.lock_timer = self.root.after(1000, check_activity)
        
        self.lock_timer = self.root.after(1000, check_activity)

    def show_lock_warning(self):
        self.warning_dialog = tk.Toplevel(self.root)
        self.warning_dialog.title("Inactivity Warning")
        self.warning_dialog.geometry("300x150")
        self.warning_dialog.resizable(False, False)
        
        # Center the dialog
        self.warning_dialog.update_idletasks()
        x = (self.warning_dialog.winfo_screenwidth() - self.warning_dialog.winfo_reqwidth()) // 2
        y = (self.warning_dialog.winfo_screenheight() - self.warning_dialog.winfo_reqheight()) // 2
        self.warning_dialog.geometry(f"+{x}+{y}")
        
        tk.Label(self.warning_dialog, text="Still there?", font=("Arial", 14, "bold")).pack(pady=10)
        
        countdown_label = tk.Label(self.warning_dialog, text="", font=("Arial", 12))
        countdown_label.pack(pady=10)
        
        def update_countdown(seconds_left):
            if self.warning_dialog and self.warning_dialog.winfo_exists():
                countdown_label.config(text=f"Locking in {seconds_left} seconds...")
                if seconds_left > 0:
                    self.warning_dialog.after(1000, lambda: update_countdown(seconds_left - 1))
                else:
                    self.warning_dialog.destroy()
                    self.warning_dialog = None
                    self.auto_lock()
        
        update_countdown(WARNING_BEFORE_LOCK)
        
        def cancel_lock():
            self.update_activity()
        
        tk.Button(self.warning_dialog, text="I'm here!", command=cancel_lock).pack(pady=10)
        
        self.warning_dialog.bind("<Button-1>", self.update_activity)
        self.warning_dialog.bind("<Key>", self.update_activity)

    def auto_lock(self):
        if not self.is_locked:
            self.lock_vault()

    def manual_lock(self):
        self.lock_vault()

    def lock_vault(self):
        self.is_locked = True
        self.storage.clear_keys()
        
        # Hide main window
        self.root.withdraw()
        
        # Show lock screen
        lock_screen = LockScreen(self.root, self.unlock_vault)
        
        # Ensure the lock screen is visible
        lock_screen.update()
        lock_screen.deiconify()
        lock_screen.lift()
        lock_screen.focus_force()

    def unlock_vault(self, password):
        try:
            # Try to reinitialize storage with provided password
            new_storage = SecureStorage(password)
            new_storage.initialize_file()
            notes, counter = new_storage.load_notes()
            
            # Success - update storage and notes
            self.storage = new_storage
            self.notes = notes
            self.counter = counter
            self.is_locked = False
            
            # Show main window and restart activity monitor
            self.root.deiconify()
            self.refresh_display()
            self.last_activity = time.time()
            self.start_activity_monitor()
            
            return True
        except Exception:
            return False

    def on_closing(self):
        if self.lock_timer:
            self.root.after_cancel(self.lock_timer)
        self.storage.clear_keys()
        self.root.destroy()

def get_password_gui(title="Password", prompt="Enter password:", confirm=False):
    """Use built-in dialogs for better macOS compatibility"""
    root = tk.Tk()
    root.withdraw()
    
    password = simpledialog.askstring(title, prompt, show='*', parent=root)
    
    if password and confirm:
        confirm_password = simpledialog.askstring(title, "Confirm password:", show='*', parent=root)
        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            root.destroy()
            return None
    
    root.destroy()
    return password

def main():
    # Check if encrypted file exists
    if os.path.exists(ENC_FILE):
        # File exists, ask for password to unlock
        password = get_password_gui(title="Unlock Secure Notes", 
                                  prompt="Enter password to unlock notes:")
    else:
        # No file exists, create new vault
        password = get_password_gui(title="Create New Vault", 
                                  prompt="Create a password for your new vault:", 
                                  confirm=True)
    
    if password is None:  # User cancelled
        return
    
    try:
        storage = SecureStorage(password)
        storage.initialize_file()
        
        # Test decryption
        try:
            storage.load_notes()
        except Exception as e:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Error", f"Failed to access vault: {str(e)}")
            root.destroy()
            return
        
        root = tk.Tk()
        app = SecureNotesApp(root, storage)
        root.mainloop()
    except Exception as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error", f"Application error: {str(e)}")
        root.destroy()
    finally:
        if 'storage' in locals():
            storage.clear_keys()

if __name__ == "__main__":
    main()

# End of File