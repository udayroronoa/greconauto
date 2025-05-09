import os
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, simpledialog
from datetime import datetime
import html
import signal
import sys

# --- TOOLS ---
TOOLS = {
    "Nmap": lambda target, mode: f"nmap {'-T4 -A' if mode == 'aggressive' else '-T1 -sS'} {target}",
    "Gobuster": lambda target, mode: f"gobuster dir -u http://{target} -w /usr/share/wordlists/dirb/common.txt {'-t 50' if mode == 'aggressive' else '-t 1'}",
    "theHarvester": lambda target, mode: f"theHarvester -d {target} -b all",
    "WhatWeb": lambda target, mode: f"whatweb {target}",
    "Sublist3r": lambda target, mode: f"sublist3r -d {target}",
    "Nikto": lambda target, mode: f"nikto -h http://{target}",
    "WPScan": lambda target, mode: f"wpscan --url http://{target} --enumerate u,vp,vt --disable-tls-checks",
    "Nuclei": lambda target, mode: f"nuclei -u http://{target} -severity high,critical -o nuclei_results.txt"
}

# --- Run Command ---
def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=180)
        return result.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode(errors='ignore')}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out."

# --- Save Report ---
def save_report_to_file(raw_output, target):
    report_type = simpledialog.askstring("Save Format", "Save as (txt/html)?", initialvalue="txt")
    time_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    if report_type and report_type.lower() == "html":
        report_html = f"""
        <html>
        <head>
            <title>ReconAutomator Report - {target}</title>
            <style>
                body {{ font-family: Consolas, monospace; background: #f4f4f4; color: #333; padding: 20px; }}
                h1 {{ color: #1a73e8; }}
                pre {{ background: #e0e0e0; color: #333; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                .section {{ margin-bottom: 30px; }}
            </style>
        </head>
        <body>
            <h1>ReconAutomator Report</h1>
            <div><strong>Target:</strong> {html.escape(target)}</div>
            <div><strong>Time:</strong> {time_now}</div>

            <div class="section">
                <h2>Raw Output</h2>
                <pre>{html.escape(raw_output)}</pre>
            </div>
        </body>
        </html>
        """
        filetypes = [("HTML Files", "*.html")]
        default_ext = ".html"
        data_to_save = report_html.strip()
    else:
        report_txt = f"""
ReconAutomator Report
Target: {target}
Time: {time_now}

{'='*40}
[+] Raw Output
{'='*40}
{raw_output}
        """
        filetypes = [("Text Files", "*.txt")]
        default_ext = ".txt"
        data_to_save = report_txt.strip()

    filepath = filedialog.asksaveasfilename(
        defaultextension=default_ext,
        filetypes=filetypes,
        title="Save Scan Report"
    )

    if filepath:
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(data_to_save)
            messagebox.showinfo("Report Saved", f"Report saved to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save file:\n{e}")

# --- Run Scan ---
def run_scan(target, mode_var, output_box, save_button_var):
    mode = mode_var.get()
    output_box.config(state='normal')
    output_box.delete(1.0, 'end')
    combined_output = ""

    for tool, command_func in TOOLS.items():
        header = f"\n{'='*40}\n[+] Running {tool}...\n{'='*40}\n"
        output_box.insert('end', header)
        output_box.update_idletasks()
        result = run_command(command_func(target, mode))

        if tool == "Nuclei":
            try:
                with open("nuclei_results.txt", "r", encoding="utf-8") as f:
                    result = f.read()
            except:
                result = "[!] Could not read nuclei output file."

        combined_output += f"{header}{result}\n"
        output_box.insert('end', result + "\n")
        output_box.update_idletasks()

    output_box.config(state='disabled')

    save_button_var['raw'] = combined_output
    save_button_var['target'] = target
    save_button_var['button'].config(state='normal')

# --- Build GUI ---
def build_gui():
    global root  # Define root globally for signal handling
    root = tk.Tk()
    root.title("ReconAutomator - GUI")
    root.geometry("1000x700")
    root.configure(bg="#f4f4f4")

    style = ttk.Style(root)
    style.theme_use('default')
    style.configure("TLabel", background="#f4f4f4", foreground="#1a73e8", font=("Helvetica", 12))
    style.configure("TButton", background="#e0e0e0", foreground="#1a73e8")
    style.configure("TEntry", fieldbackground="#e0e0e0", foreground="#1a73e8")
    style.configure("TOptionMenu", background="#e0e0e0", foreground="#1a73e8")

    ttk.Label(root, text="ReconAutomator", font=("Helvetica", 20, "bold"), foreground="#1a73e8").pack(pady=10)

    frame = ttk.Frame(root)
    frame.pack(pady=10)

    ttk.Label(frame, text="Target (Domain/IP):").grid(row=0, column=0, padx=5)
    target_entry = ttk.Entry(frame, width=50)
    target_entry.grid(row=0, column=1, padx=5)

    mode_var = tk.StringVar(value="aggressive")
    ttk.Label(frame, text="Mode:").grid(row=0, column=2, padx=5)
    mode_menu = ttk.OptionMenu(frame, mode_var, "aggressive", "aggressive", "stealth")
    mode_menu.grid(row=0, column=3, padx=5)

    output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Courier", 10), width=120, height=30, bg="#e0e0e0", fg="#333")
    output_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    output_box.config(state=tk.DISABLED)

    save_button_var = {'raw': '', 'target': '', 'button': None}

    start_button = ttk.Button(root, text="Start Scan",
                              command=lambda: threading.Thread(
                                  target=run_scan,
                                  args=(target_entry.get().strip(), mode_var, output_box, save_button_var),
                                  daemon=True
                              ).start())
    start_button.pack(pady=10)

    save_button = ttk.Button(root, text="Save Report",
                             command=lambda: save_report_to_file(
                                 save_button_var['raw'],
                                 save_button_var['target']
                             ))
    save_button.pack(pady=5)
    save_button.config(state='disabled')
    save_button_var['button'] = save_button

    # Signal handling to gracefully close the Tkinter window
    signal.signal(signal.SIGINT, handle_exit_signal)

    root.mainloop()

# --- Handle Exit Signal ---
def handle_exit_signal(signum, frame):
    print("Exiting...")
    root.quit()  # Gracefully close the Tkinter window
    sys.exit(0)

# --- MAIN ---
if __name__ == "__main__":
    build_gui()
