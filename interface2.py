import os
import tkinter as tk
from tkinter import filedialog, messagebox


def check_pe_file(file_content, signatures):
    """
    检查PE文件的特征码。

    :param file_content: 文件内容
    :param signatures: 特征库
    :return: 是否发现恶意软件特征码
    """
    for signature in signatures.values():
        if signature in file_content:
            return True
    return False

# 特征库，存储特征码
signatures = {
    'malware1': b'\x12\x34\x56\x78',  # 特征码1
    'malware2': b'\x90\x12\x34\x56'   # 特征码2
}

def scan_files(directory):
    malware_found = False
    for root, dirs, files in os.walk(directory):
        for file in files:
            #在此逐个文件扫描
            file_path = os.path.join(root, file)
            try:
                # 检查文件大小，这里以10MB为例，可以根据需要调整
                if os.path.getsize(file_path) > 10 * 1024 * 1024:
                    print(f"Skip large files: {file_path}")
                    continue

                # 读取文件内容
                with open(file_path, 'rb') as f:
                    file_content = f.read()

                # 检查文件类型，这里以PE文件为例，可以根据需要添加其他类型
                if file.endswith('.exe') or file.endswith('.dll'):
                    # 假设我们有一个函数来检查PE文件的特征码
                    if check_pe_file(file_content, signatures):
                        print(f"The malware signature code was found in the file：{file_path}")
                        messagebox.showwarning("MALWARE SIGNATURE DETECTED",
                                               f"Warning! A virus has been detected in \n {file_path} \nPlease clean it up promptly.")

                    else:
                        print(f"file {file_path} No malware signature found.")
                else:
                    print(f"file {file_path} Not a PE file, skip scanning.")

            except Exception as e:
                print(f"An error occurred while scanning file {file_path}: {str(e)}")


def scan_selected_directory():
    directory = filedialog.askdirectory()
    if directory:
        malware_found = scan_files(directory)
        messagebox.showwarning("MALWARE SIGNATURE DETECTED",
                               f"Warning! A virus has been detected in \n {directory} \nPlease clean it up promptly.")

        # if malware_found:
        #     result_label.config(text="Malware detected!")
        # else:
        #     result_label.config(text="No malware found.")

app = tk.Tk()
app.title("Anti-Malware Scanner")

scan_button = tk.Button(app, text="Scan Directory", command=scan_selected_directory)
scan_button.pack(pady=20)

result_label = tk.Label(app, text="Select a directory to scan")
result_label.pack(pady=20)

app.mainloop()