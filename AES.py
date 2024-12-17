from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import tkinter as tk
from tkinter import messagebox  

class AES_GUI:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption")

        # Tạo nhãn dán
        self.text_label = tk.Label(master, text="Text:")
        self.text_label.grid(row=0, column=0, sticky="w")
        self.key_label = tk.Label(master, text="Key:")
        self.key_label.grid(row=1, column=0, sticky="w")
        self.output_label = tk.Label(master, text="Output:")
        self.output_label.grid(row=2, column=0, sticky="w")

        # Tạo các trường nhập liệu
        self.text_input = tk.Entry(master, width=50)
        self.text_input.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        self.key_input = tk.Entry(master, width=50)
        self.key_input.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # Tạo trường xuất dữ liệu
        self.output_text = tk.Text(master, height=10, width=50)
        self.output_text.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # Tạo các nút nhấn
        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.grid(row=3, column=0, padx=5, pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.grid(row=3, column=1, padx=5, pady=5)

        # Thêm nút HDSD
        self.help_button = tk.Button(master, text="HDSD", command=self.show_help)
        self.help_button.grid(row=3, column=2, padx=5, pady=5)

    def encrypt(self):
        text = self.text_input.get()
        key = self.key_input.get()

        # Kiểm tra độ dài key
        if len(key) not in (16, 24, 32):
            messagebox.showerror("Error", "Key phải dài 16, 24 hoặc 32 ký tự.")
            return

        # Mã hóa văn bản
        cipher = AES.new(key.encode(), AES.MODE_CBC)
        iv = cipher.iv  # Giá trị khởi tạo IV
        ciphertext = cipher.encrypt(pad(text.encode(), AES.block_size))
        
        # Xuất dữ liệu mã hóa
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, f"IV: {iv.hex()}\nCiphertext: {ciphertext.hex()}")

    def decrypt(self):
        output_data = self.output_text.get("1.0", tk.END).strip()
        key = self.key_input.get()

        # Kiểm tra độ dài key
        if len(key) not in (16, 24, 32):
            messagebox.showerror("Error", "Key phải dài 16, 24 hoặc 32 ký tự.")
            return

        try:
            # Tách IV và Ciphertext
            lines = output_data.split("\n")
            iv = bytes.fromhex(lines[0].split(": ")[1])
            ciphertext = bytes.fromhex(lines[1].split(": ")[1])

            # Giải mã văn bản
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv=iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)

            # Hiển thị văn bản gốc
            self.text_input.delete(0, tk.END)
            self.text_input.insert(0, decrypted.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Lỗi khi giải mã: {e}")

    def show_help(self):
        """Hiển thị hướng dẫn sử dụng ứng dụng."""
        usage_instructions = (
            "1. Nhập Text và Key:\n"
            "   - Text: Nội dung cần mã hóa hoặc để trống khi giải mã.\n"
            "   - Key: Chuỗi bí mật dài 16, 24 hoặc 32 ký tự.\n"
            "2. Nhấn 'Encrypt' để mã hóa:\n"
            "   - Kết quả mã hóa sẽ xuất hiện ở Output.\n"
            "3. Copy IV và Ciphertext để lưu trữ.\n"
            "4. Nhập lại IV, Ciphertext và Key khi cần giải mã.\n"
            "5. Nhấn 'Decrypt' để giải mã và xem Text gốc."
        )
        messagebox.showinfo("Hướng dẫn sử dụng", usage_instructions)


if __name__ == '__main__':
    root = tk.Tk()
    app = AES_GUI(root)
    root.mainloop()
