import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

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

def open_file(file_path):
    """
    打开文件所在的目录。
    """
    os.startfile(os.path.dirname(file_path))

def delete_file(file_path):
    """
    删除文件。
    """
    try:
        os.remove(file_path)
        print(f"Deleted file: {file_path}")
    except Exception as e:
        print(f"Failed to delete file {file_path}: {str(e)}")

def on_open_button_click(event):
    """
    打开按钮点击事件处理函数。
    """
    # 获取选中行的数据
    item = event.widget.tree.item(event.widget.focus())
    file_path = item['values'][1]
    open_file(file_path)

def on_delete_button_click(event):
    """
    删除按钮点击事件处理函数。
    """
    # 获取选中行的数据
    item = event.widget.tree.item(event.widget.focus())
    file_path = item['values'][1]
    delete_file(file_path)
    event.widget.tree.delete(event.widget.focus())  # 删除表格中的行

def scan_files(directory, tree):
    """
    扫描目录中的文件，并在表格中显示恶意软件文件。
    """
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if os.path.getsize(file_path) > 10 * 1024 * 1024:
                    print(f"Skip large files: {file_path}")
                    continue

                with open(file_path, 'rb') as f:
                    file_content = f.read()

                if file.endswith('.exe') or file.endswith('.dll'):
                    if check_pe_file(file_content, signatures):
                        print(f"The malware signature code was found in the file: {file_path}")
                        tree.insert('', 'end', values=(file, file_path,  "Delete"))
                    else:
                        print(f"No malware signature found in file: {file_path}")
                else:
                    print(f"Not a PE file, skip scanning: {file_path}")
            except Exception as e:
                print(f"An error occurred while scanning file {file_path}: {str(e)}")

def scan_selected_directory(tree):
    """
    选择目录并扫描。
    """
    directory = filedialog.askdirectory()
    if directory:
        scan_files(directory, tree)
        messagebox.showinfo("Scan Complete", "Scan complete.")

app = tk.Tk()
app.title("Anti-Malware Scanner")

# 创建表格
tree = ttk.Treeview(app, columns=('File', 'Path',  'Delete'), show='headings')
tree.heading('File', text='File Name')
tree.heading('Path', text='File Path')
# tree.heading('Open', text='Open')
tree.heading('Delete', text='recommendation')
tree.column('File', width=100)
tree.column('Path', width=400)
# tree.column('Open', width=100)
tree.column('Delete', width=100)
tree.pack(pady=20)

# 创建滚动条
scrollbar = ttk.Scrollbar(app, command=tree.yview)
tree.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 创建按钮
scan_button = tk.Button(app, text="Scan Directory", command=lambda: scan_selected_directory(tree))
scan_button.pack(pady=20)

app.mainloop()