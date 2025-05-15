import tkinter as tk
from tkinter import filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from crypto_utils import encrypt, decrypt
from stegano_image import hide_file_in_image, extract_file_from_image
from stegano_audio import hide_file_in_audio, extract_file_from_audio
import os
import threading
import time
from PIL import Image, ImageTk
import io

# Custom theme configuration
style = tb.Style("darkly")
style.configure('TButton', font=('Segoe UI', 10))
style.configure('success.TButton', font=('Segoe UI', 10, 'bold'))
style.configure('warning.TButton', font=('Segoe UI', 10, 'bold'))
style.configure('TLabel', font=('Segoe UI', 10))
style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'))
style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'))
style.configure('TEntry', font=('Consolas', 12))
style.configure('TFrame', background=style.colors.bg)


class AnimatedText(tb.Text):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tag_configure('success', foreground='#2ecc71')
        self.tag_configure('error', foreground='#e74c3c')
        self.tag_configure('info', foreground='#3498db')
        self.tag_configure('warning', foreground='#f39c12')

    def log(self, msg, level='info'):
        self.config(state=tk.NORMAL)
        self.insert(tk.END, f"{msg}\n", level)
        self.see(tk.END)
        self.config(state=tk.DISABLED)
        with open("logs.txt", "a") as f:
            f.write(f"[{level.upper()}] {msg}\n")


class SteganoApp(tb.Window):
    def __init__(self):
        super().__init__(themename="darkly")
        self.title("🔐 SecureStegano - Advanced Data Hiding Tool")
        self.geometry("900x700")
        self.minsize(800, 600)
        self.attributes('-alpha', 0.0)
        self.after(0, self.fade_in)

        # App variables
        self.selected_file = None
        self.file_type = None
        self.file_preview = None
        self.operation_in_progress = False

        # Setup UI
        self.create_widgets()
        self.create_menu()

    def fade_in(self):
        alpha = self.attributes('-alpha')
        if alpha < 1.0:
            alpha += 0.05
            self.attributes('-alpha', alpha)
            self.after(40, self.fade_in)

    def create_menu(self):
        menu = tk.Menu(self)

        # File menu
        file_menu = tk.Menu(menu, tearoff=0)
        file_menu.add_command(label="Open Carrier File", command=self.select_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)

        # Help menu
        help_menu = tk.Menu(menu, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_docs)

        menu.add_cascade(label="File", menu=file_menu)
        menu.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menu)

    def create_widgets(self):
        # Main container
        main_frame = tb.Frame(self)
        main_frame.pack(fill=BOTH, expand=YES, padx=10, pady=10)

        # Header
        header_frame = tb.Frame(main_frame)
        header_frame.pack(fill=X, pady=(0, 10))

        tb.Label(header_frame, text="SecureStegano", style='Title.TLabel').pack(side=LEFT)
        tb.Label(header_frame, text="Hide and extract files with encryption", style='Header.TLabel').pack(side=LEFT,
                                                                                                          padx=10)

        # File selection area
        file_frame = tb.LabelFrame(main_frame, text="Carrier File", padding=10)
        file_frame.pack(fill=X, pady=5)

        self.select_btn = tb.Button(
            file_frame,
            text="Select Image/Audio File",
            bootstyle=(OUTLINE, INFO),
            command=self.select_file,
            width=20
        )
        self.select_btn.pack(side=LEFT, padx=5)

        self.file_label = tb.Label(file_frame, text="No file selected", bootstyle=INFO)
        self.file_label.pack(side=LEFT, padx=10)

        # Preview area
        self.preview_frame = tb.Frame(main_frame, height=150)
        self.preview_frame.pack(fill=X, pady=10)
        self.preview_label = tb.Label(self.preview_frame)
        self.preview_label.pack()

        # Password area
        password_frame = tb.LabelFrame(main_frame, text="Security", padding=10)
        password_frame.pack(fill=X, pady=5)

        tb.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=W, padx=5)
        self.password_entry = tb.Entry(password_frame, show="•", font=('Consolas', 12))
        self.password_entry.grid(row=0, column=1, sticky=EW, padx=5)

        tb.Label(password_frame, text="Confirm:").grid(row=1, column=0, sticky=W, padx=5)
        self.confirm_entry = tb.Entry(password_frame, show="•", font=('Consolas', 12))
        self.confirm_entry.grid(row=1, column=1, sticky=EW, padx=5)

        password_frame.columnconfigure(1, weight=1)

        # Operation buttons
        btn_frame = tb.Frame(main_frame)
        btn_frame.pack(fill=X, pady=15)

        self.hide_btn = tb.Button(
            btn_frame,
            text="Hide File",
            bootstyle=SUCCESS,
            command=self.hide_file,
            width=15
        )
        self.hide_btn.pack(side=LEFT, expand=YES, padx=10)

        self.extract_btn = tb.Button(
            btn_frame,
            text="Extract File",
            bootstyle=WARNING,
            command=self.extract_file,
            width=15
        )
        self.extract_btn.pack(side=LEFT, expand=YES, padx=10)

        # Progress bar
        self.progress = tb.Progressbar(
            main_frame,
            maximum=100,
            mode='determinate',
            bootstyle="success-striped"
        )

        # Log area
        log_frame = tb.LabelFrame(main_frame, text="Activity Log", padding=5)
        log_frame.pack(fill=BOTH, expand=YES)

        self.log_box = AnimatedText(
            log_frame,
            height=10,
            font=('Consolas', 9),
            wrap=WORD,
            padx=5,
            pady=5
        )
        self.log_box.pack(fill=BOTH, expand=YES)

        # Add scrollbar
        scrollbar = tb.Scrollbar(log_frame, command=self.log_box.yview)
        scrollbar.pack(side=RIGHT, fill=Y)
        self.log_box.config(yscrollcommand=scrollbar.set)
        self.log_box.config(state=tk.DISABLED)

        # Status bar
        self.status = tb.Label(
            main_frame,
            text="Ready",
            bootstyle=(INVERSE, SECONDARY),
            anchor=W
        )
        self.status.pack(fill=X, pady=(5, 0))

    def update_status(self, message, level='info'):
        colors = {
            'info': style.colors.secondary,
            'success': style.colors.success,
            'warning': style.colors.warning,
            'error': style.colors.danger
        }
        self.status.config(
            text=message,
            bootstyle=(INVERSE, level.upper())
        )

    def select_file(self):
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", "Please wait for the current operation to complete.")
            return

        file_path = filedialog.askopenfilename(filetypes=[
            ("Image files", "*.png *.bmp *.jpg *.jpeg"),
            ("Audio files", "*.wav *.mp3")
        ])

        if file_path:
            self.selected_file = file_path
            filename = os.path.basename(file_path)
            self.file_label.config(text=filename)
            self.update_status(f"Selected: {filename}")
            self.log_box.log(f"Selected carrier file: {file_path}", 'info')

            # Determine file type
            ext = os.path.splitext(file_path)[1].lower()
            if ext in [".png", ".bmp", ".jpg", ".jpeg"]:
                self.file_type = "image"
                self.show_image_preview(file_path)
            elif ext in [".wav", ".mp3"]:
                self.file_type = "audio"
                self.show_audio_preview(file_path)
            else:
                self.file_type = None
                messagebox.showerror("Error", "Unsupported file type!")

    def show_image_preview(self, image_path):
        try:
            # Clear previous preview
            for widget in self.preview_frame.winfo_children():
                widget.destroy()

            # Load and resize image
            img = Image.open(image_path)
            img.thumbnail((300, 150))

            # Convert to PhotoImage
            self.file_preview = ImageTk.PhotoImage(img)
            preview_label = tb.Label(self.preview_frame, image=self.file_preview)
            preview_label.pack()

            # Show file info
            info_label = tb.Label(
                self.preview_frame,
                text=f"Dimensions: {img.width}x{img.height} | Size: {os.path.getsize(image_path) / 1024:.1f} KB",
                bootstyle=INFO
            )
            info_label.pack(pady=5)

        except Exception as e:
            self.log_box.log(f"Preview error: {str(e)}", 'error')

    def show_audio_preview(self, audio_path):
        for widget in self.preview_frame.winfo_children():
            widget.destroy()

        # Simple audio file info display
        size_kb = os.path.getsize(audio_path) / 1024
        info_text = f"Audio File | Size: {size_kb:.1f} KB"

        icon_label = tb.Label(
            self.preview_frame,
            text="🔊",
            font=('Arial', 48),
            bootstyle=INFO
        )
        icon_label.pack(pady=5)

        info_label = tb.Label(
            self.preview_frame,
            text=info_text,
            bootstyle=INFO
        )
        info_label.pack()

    def validate_password(self):
        password = self.password_entry.get()
        confirm = self.confirm_entry.get()

        if not password:
            messagebox.showerror("Error", "Password cannot be empty!")
            return False

        if password != confirm:
            messagebox.showerror("Error", "Passwords do not match!")
            return False

        if len(password) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters!")
            return False

        return True

    def run_thread(self, func):
        if self.operation_in_progress:
            messagebox.showwarning("Operation in Progress", "Please wait for the current operation to complete.")
            return

        self.operation_in_progress = True
        self.disable_ui()

        def wrapper():
            try:
                func()
            except Exception as e:
                self.log_box.log(f"Operation failed: {str(e)}", 'error')
                messagebox.showerror("Error", f"Operation failed: {str(e)}")
            finally:
                self.operation_in_progress = False
                self.enable_ui()
                self.progress.pack_forget()
                self.progress['value'] = 0
                self.update_status("Ready", 'info')

        t = threading.Thread(target=wrapper, daemon=True)
        t.start()

    def disable_ui(self):
        self.select_btn.config(state=tk.DISABLED)
        self.hide_btn.config(state=tk.DISABLED)
        self.extract_btn.config(state=tk.DISABLED)
        self.password_entry.config(state=tk.DISABLED)
        self.confirm_entry.config(state=tk.DISABLED)
        self.progress.pack(fill=X, pady=10)
        self.progress.start()

    def enable_ui(self):
        self.select_btn.config(state=tk.NORMAL)
        self.hide_btn.config(state=tk.NORMAL)
        self.extract_btn.config(state=tk.NORMAL)
        self.password_entry.config(state=tk.NORMAL)
        self.confirm_entry.config(state=tk.NORMAL)
        self.progress.stop()

    def hide_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a carrier file first!")
            return

        if not self.validate_password():
            return

        file_to_hide = filedialog.askopenfilename(title="Select file to hide")
        if not file_to_hide:
            return

        def task():
            try:
                self.update_status("Hiding file...", 'info')
                self.log_box.log(f"Starting hide operation with {file_to_hide}", 'info')

                password = self.password_entry.get()

                with open(file_to_hide, "rb") as f:
                    data = f.read()

                self.log_box.log("Encrypting file content...", 'info')
                encrypted = encrypt(data, password)

                if self.file_type == "image":
                    out_path = filedialog.asksaveasfilename(
                        defaultextension=".png",
                        filetypes=[("PNG Image", "*.png")],
                        title="Save steganographic image as"
                    )
                    if out_path:
                        self.log_box.log("Hiding file in image...", 'info')
                        hide_file_in_image(self.selected_file, out_path, encrypted)
                        self.log_box.log(f"File successfully hidden in {out_path}", 'success')
                        messagebox.showinfo("Success", "File hidden successfully in the image!")
                else:  # audio
                    out_path = filedialog.asksaveasfilename(
                        defaultextension=".wav",
                        filetypes=[("WAV Audio", "*.wav")],
                        title="Save steganographic audio as"
                    )
                    if out_path:
                        self.log_box.log("Hiding file in audio...", 'info')
                        hide_file_in_audio(self.selected_file, out_path, encrypted)
                        self.log_box.log(f"File successfully hidden in {out_path}", 'success')
                        messagebox.showinfo("Success", "File hidden successfully in the audio!")

                self.update_status("Operation completed successfully", 'success')

            except Exception as e:
                self.log_box.log(f"Error during hide operation: {str(e)}", 'error')
                self.update_status("Operation failed", 'error')
                raise

        self.run_thread(task)

    def extract_file(self):
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a carrier file first!")
            return

        if not self.validate_password():
            return

        def task():
            try:
                self.update_status("Extracting file...", 'info')
                self.log_box.log(f"Starting extract operation from {self.selected_file}", 'info')

                password = self.password_entry.get()

                if self.file_type == "image":
                    self.log_box.log("Extracting from image...", 'info')
                    encrypted = extract_file_from_image(self.selected_file)
                else:
                    self.log_box.log("Extracting from audio...", 'info')
                    encrypted = extract_file_from_audio(self.selected_file)

                self.log_box.log("Decrypting file content...", 'info')
                decrypted = decrypt(encrypted, password)

                save_path = filedialog.asksaveasfilename(
                    title="Save extracted file as",
                    defaultextension=".*"
                )

                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(decrypted)
                    self.log_box.log(f"File successfully extracted to {save_path}", 'success')
                    messagebox.showinfo("Success", "File extracted successfully!")

                self.update_status("Operation completed successfully", 'success')

            except Exception as e:
                self.log_box.log(f"Error during extract operation: {str(e)}", 'error')
                self.update_status("Operation failed", 'error')
                raise

        self.run_thread(task)

    def show_about(self):
        about_text = """
SecureStegano - Advanced Data Hiding Tool
Version 2.0

This application allows you to:
- Hide any file within image or audio files
- Extract hidden files with password protection
- All data is encrypted before hiding

Developed with Python and Tkinter
"""
        messagebox.showinfo("About SecureStegano", about_text.strip())

    def show_docs(self):
        docs_text = """
HOW TO USE:

1. Select a carrier file (image or audio)
2. Enter a strong password (and confirm)
3. Choose operation:
   - Hide: Select a file to hide inside the carrier
   - Extract: Recover a hidden file from the carrier

SECURITY NOTES:
- Always use strong passwords
- Keep your carrier files safe
- Without the password, hidden files cannot be recovered
"""
        messagebox.showinfo("Documentation", docs_text.strip())


if __name__ == "__main__":
    app = SteganoApp()
    app.mainloop()
