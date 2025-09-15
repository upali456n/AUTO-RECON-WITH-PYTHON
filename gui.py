import os
import sys
import tkinter as tk
from tkinter import messagebox, scrolledtext, Toplevel, Label, Entry, Button
from PIL import Image, ImageTk
import threading
from main1 import run_full_recon, send_email_report

# --------------------------
# Universal Paths
# --------------------------
if getattr(sys, "frozen", False):
    BASE_DIR = sys._MEIPASS          # read-only resources bundled inside exe
    APP_DIR = os.path.dirname(sys.executable)  # folder where exe lives (writable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    APP_DIR = BASE_DIR

SAVE_PATH = os.path.join(APP_DIR, "reports")

# --------------------------
# Typewriter Effect
# --------------------------
def typewriter(widget, text, delay=30):
    def inner():
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        for i, char in enumerate(text):
            widget.insert(tk.END, char)
            widget.see(tk.END)
            widget.update()
            widget.after(delay)
        widget.config(state=tk.DISABLED)
    threading.Thread(target=inner, daemon=True).start()

# --------------------------
# GUI APP
# --------------------------
class ReconGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyber Recon Tool")
        self.root.geometry("900x650")

        # --- Background Setup ---
        bg_path = os.path.join(BASE_DIR, "bg.jpg")
        self.bg_img_raw = Image.open(bg_path)
        self.bg_img_raw = self.bg_img_raw.resize((900, 650))
        self.bg_img = ImageTk.PhotoImage(self.bg_img_raw)

        self.bg_label = tk.Label(self.root, image=self.bg_img)
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.root.bind("<Configure>", self.resize_bg)

        # --- Title ---
        self.title_label = tk.Label(
            self.root, text="🔒⚡ Automatically Recon Tool ⚡🔒",
            font=("Consolas", 20, "bold"), bg="black", fg="cyan"
        )
        self.title_label.pack(pady=15)

        # --- Target URL ---
        self.url_entry = tk.Entry(
            self.root, font=("Consolas", 14),
            width=40, bg="black", fg="lime", insertbackground="lime"
        )
        self.url_entry.pack(pady=10)
        self.url_entry.insert(0, "")

        # Buttons
        btn_frame = tk.Frame(self.root, bg="black")
        btn_frame.pack(pady=5)

        self.run_btn = tk.Button(
            btn_frame, text="Run Recon", font=("Consolas", 14, "bold"),
            command=self.run_recon_thread, bg="lime", fg="black"
        )
        self.run_btn.grid(row=0, column=0, padx=10)

        self.clear_btn = tk.Button(
            btn_frame, text="Clear Output", font=("Consolas", 12),
            command=self.clear_output, bg="orange", fg="black"
        )
        self.clear_btn.grid(row=0, column=1, padx=10)

        self.info_btn = tk.Button(
            btn_frame, text="Project Info", font=("Consolas", 12),
            command=self.open_project_info, bg="cyan", fg="black"
        )
        self.info_btn.grid(row=0, column=2, padx=10)

        # --- Output Box ---
        self.output_box = scrolledtext.ScrolledText(
            self.root, width=100, height=18, font=("Consolas", 10),
            bg="black", fg="lime", insertbackground="lime"
        )
        self.output_box.pack(padx=10, pady=10)
        self.output_box.config(state=tk.DISABLED)

        # --- Email Report Button ---
        self.email_btn = tk.Button(
            self.root, text="Send Email Report", font=("Consolas", 12, "bold"),
            command=self.open_email_popup, bg="red", fg="white"
        )
        self.email_btn.pack(pady=5)

        self.last_pdf = None

    def resize_bg(self, event):
        resized = self.bg_img_raw.resize((event.width, event.height))
        self.bg_img = ImageTk.PhotoImage(resized)
        self.bg_label.config(image=self.bg_img)
        self.bg_label.image = self.bg_img

    def run_recon_thread(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Error", "Please enter a target URL!")
            return

        self.clear_output()
        threading.Thread(target=self.run_recon, args=(url,), daemon=True).start()

    def run_recon(self, url):
        try:
            results, pdf_path = run_full_recon(url, SAVE_PATH)
            self.last_pdf = pdf_path
            typewriter(self.output_box, results)
        except Exception as e:
            typewriter(self.output_box, f"[!] Error: {e}")

    def clear_output(self):
        self.output_box.config(state=tk.NORMAL)
        self.output_box.delete(1.0, tk.END)
        self.output_box.config(state=tk.DISABLED)

    # --------------------------
    # Open Project_Info.pdf
    # --------------------------
    def open_project_info(self):
        pdf_path = os.path.join(BASE_DIR, "Project_Info.pdf")
        if os.path.exists(pdf_path):
            os.startfile(pdf_path)  # Windows only
        else:
            messagebox.showerror("Error", "Project_Info.pdf not found in project folder!")

    # --------------------------
    # POPUP for Email Details
    # --------------------------
    def open_email_popup(self):
        if not self.last_pdf:
            messagebox.showerror("Error", "Run Recon first to generate a PDF!")
            return

        popup = Toplevel(self.root)
        popup.title("Send Email Report")
        popup.geometry("400x300")

        Label(popup, text="Sender Email:").pack(pady=5)
        sender_entry = Entry(popup, width=40)
        sender_entry.pack(pady=5)

        Label(popup, text="App Password:").pack(pady=5)
        password_entry = Entry(popup, width=40, show="*")
        password_entry.pack(pady=5)

        Label(popup, text="Recipient Email:").pack(pady=5)
        recipient_entry = Entry(popup, width=40)
        recipient_entry.pack(pady=5)

        def send_now():
            sender = sender_entry.get().strip()
            pwd = password_entry.get().strip()
            recipient = recipient_entry.get().strip()

            if not sender or not pwd or not recipient:
                messagebox.showerror("Error", "All fields are required!")
                return

            threading.Thread(
                target=self.send_email,
                args=(sender, pwd, recipient),
                daemon=True
            ).start()
            popup.destroy()

        Button(popup, text="Send Email", command=send_now, bg="green", fg="white").pack(pady=15)

    def send_email(self, sender, password, recipient):
        status = send_email_report(sender, password, recipient, self.last_pdf)
        self.output_box.config(state=tk.NORMAL)
        self.output_box.insert(tk.END, "\n" + status + "\n")
        self.output_box.see(tk.END)
        self.output_box.config(state=tk.DISABLED)


# --------------------------
# RUN APP
# --------------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = ReconGUI(root)
    root.mainloop()
