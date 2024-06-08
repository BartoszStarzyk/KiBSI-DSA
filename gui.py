import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from elGammal import elGammal
from DSA import DSA

class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature App")
        self.selected_algorithm = tk.StringVar(value="DSA")
        self.algs = {"DSA" : DSA(), "el_gammal" : elGammal(20)}
        tk.Label(root, text="Select Algorithm:").pack()
        tk.OptionMenu(root, self.selected_algorithm, "DSA", "el_gammal").pack()

        tk.Button(root, text="Generate Keys", command=self.generate_keys).pack()
        tk.Button(root, text="Sign Document", command=self.sign_document).pack()
        tk.Button(root, text="Verify Document", command=self.verify_document).pack()
        tk.Button(root, text="Export public key", command=self.save_key).pack()
        self.foreign_key = None

    def load_foreign_key(self):
        pass

    def save_key(self):
        algorithm = self.selected_algorithm.get()
        alg=self.algs[algorithm]
        filetypes = [('Text Document', '*.txt')] 
        file = filedialog.asksaveasfilename(filetypes = filetypes, defaultextension = filetypes) 
        alg.export_own_public_key(file, 'public')

    def generate_keys(self):
        algorithm = self.selected_algorithm.get()
        self.algs[algorithm].gen_key()
        messagebox.showinfo(
            "Keys Generated", f"{algorithm} keys generated successfully."
        )

    def sign_document(self):
        algorithm = self.selected_algorithm.get()
        alg=self.algs[algorithm]
        if not alg.private_key:
            messagebox.showerror("Error", f"{algorithm} keys not generated.")
            return

        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        with open(file_path, "r") as file:
            lines = [line.rstrip() for line in file]
            print(lines)
            msg = "\n".join(lines)

        sig = alg.sign(msg)

        with open(f'{file_path}_{algorithm}.sig', "w") as sig_file:
            sig_file.write(",".join(map(str, sig)))

        messagebox.showinfo(
            "Document Signed", f"Document signed and signature saved as {file_path}_{algorithm}.sig"
        )

    def verify_document(self):
        algorithm = self.selected_algorithm.get()
        alg=self.algs[algorithm]

        file_path = filedialog.askopenfilename(title="Select Document to Verify")
        if not file_path:
            return
        sig_path = filedialog.askopenfilename(title="Select Signature File")
        if not sig_path:
            return
        key_path = filedialog.askopenfilename(title="Select Public Key File")
        if not key_path:
            return

        msg = alg.load_message(file_path)

        with open(sig_path, "r") as sig_file:
            sig = tuple(map(int, sig_file.readline().split(",")))

        with open(key_path, "r") as key_file:
            key = tuple(map(int, key_file.readline().split(",")))

        if alg.verify(msg, sig, key):
            messagebox.showinfo("Verification Successful", "The document signature is valid.")
        else:
            messagebox.showerror("Verification Failed", f"Invalid signature")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
