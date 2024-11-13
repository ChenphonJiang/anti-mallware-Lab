import tkinter as tk
from tkinter import filedialog

from Scan_file import scan_files


def scan_selected_directory():
    directory = filedialog.askdirectory()
    if directory:
        malware_found = scan_files(directory)
        if malware_found:
            result_label.config(text="Malware detected!")
        else:
            result_label.config(text="No malware found.")

app = tk.Tk()
app.title("Anti-Malware Scanner")

scan_button = tk.Button(app, text="Scan Directory", command=scan_selected_directory)
scan_button.pack(pady=20)

result_label = tk.Label(app, text="Select a directory to scan")
result_label.pack(pady=20)

app.mainloop()