import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from elGammal import elGammal
from DSA import DSA
import os


class DigitalSignatureApp:
    def __init__(self, root):
        self.root = root
        root.resizable(0, 0)
        root.columnconfigure(0, weight=1)
        root.columnconfigure(1, weight=1)
        root.columnconfigure(2, weight=1)
        root.columnconfigure(3, weight=1)
        self.root.title("Digital Signature App")
        self.selected_alg_type = tk.StringVar(value="DSA")
        self.algs = {"DSA" : DSA(), "el_gammal" : elGammal(20)}
        tk.Label(root, text="Select Algorithm:").grid(column=2, row=0, columnspan=2, sticky="news")
        tk.OptionMenu(root, self.selected_alg_type, "DSA", "el_gammal").grid(column=0, row=0, columnspan=2, sticky="news")

        tk.Button(root, text="Generate Keys", command=self.generate_keys).grid(column=0, row=4, sticky='news')
        tk.Button(root, text="Sign Document", command=self.sign_document).grid(column=1, row=4, sticky='news')
        tk.Button(root, text="Verify Document", command=self.verify_document).grid(column=2, row=4, sticky='news')
        tk.Button(root, text="Save key", command=self.save_key).grid(column=3, row=4, sticky='news')

        self.Document = {"path" : None, "value" : None}
        self.Foreign_key = {"path" : None, "value" : None}
        self.Signature = {"path" : None, "value" : None}

        tk.Button(root, text="Document", command=self.load_document).grid(column=0, row=1, columnspan=2, sticky="news")
        tk.Button(root, text="Foreign Key", command=self.load_foreign_key).grid(column=0, row=2, columnspan=2, sticky="news")
        tk.Button(root, text="Signature", command=self.load_signature).grid(column=0, row=3, columnspan=2, sticky="news")

        self.docu_label = tk.Label(root, text="")
        self.docu_label.grid(column=2, row=1, columnspan=2, sticky="news")
        self.key_label = tk.Label(root, text="")
        self.key_label.grid(column=2, row=2, columnspan=2, sticky="news")
        self.sig_label = tk.Label(root, text="")
        self.sig_label.grid(column=2, row=3, columnspan=2, sticky="news")

    def load_document(self):
        filetypes = [('Text Document', '*.txt')]
        docu_path = filedialog.askopenfilename(title="Select Document File", filetypes=filetypes)
        _, docu_name = os.path.split(docu_path)
        if not docu_path:
            return
        with open(docu_path, "r") as f:
            docu = f.read()
        self.Document['path'] = docu_path
        self.Document['value'] = docu
        self.docu_label.config(text = docu_name)

    def load_foreign_key(self):
        alg_type, _ = self.get_alg()
        filetypes = [('Key File', f"{alg_type}_key.txt")]
        key_path = filedialog.askopenfilename(title="Select Foreign Public Key File", filetypes=filetypes)
        _, key_name = os.path.split(key_path)
        if not key_path:
            return
        with open(key_path, 'r') as f:
            key = tuple(map(int, f.readline().split(",")))
        self.Foreign_key['path'] = key_path
        self.Foreign_key['value'] = key
        self.key_label.config(text = key_name)

    def load_signature(self):
        alg_type, _ = self.get_alg()
        filetypes = [('Signature File', f'*_{alg_type}_sig.txt')]
        sig_path = filedialog.askopenfilename(title="Select signature File", filetypes=filetypes)
        _, sig_name = os.path.split(sig_path)
        if not sig_path:
            return
        with open(sig_path, 'r') as f:
            sig = tuple(map(int, f.readline().split(",")))
        self.Signature['path'] = sig_path
        self.Signature['value'] = sig
        self.sig_label.config(text = sig_name)

    def generate_keys(self):
            alg_type, alg = self.get_alg()
            alg.gen_key()
            messagebox.showinfo(
                "Keys Generated", f"{alg_type} keys generated successfully."
        )


    def save_key(self):
        alg_type, alg = self.get_alg()
        if alg.private_key == None or alg.public_key == None:
            messagebox.showerror("Error", f"{alg_type} key not generated")
            return 
        with open(f'{alg_type}_key.txt', 'w') as f:
            if alg_type == "DSA":
                k = (alg.q, alg.p, alg.g, alg.public_key)
            else:
                k = (alg.p, alg.g, alg.public_key)
            f.write(",".join(map(str, k)))
        messagebox.showinfo(
            "Document Signed", f"Key saved as {alg_type}_key.txt"
        )

    def get_alg(self):
        alg_type = self.selected_alg_type.get()
        alg=self.algs[alg_type]
        return alg_type,alg

    def sign_document(self):
        alg_type, alg = self.get_alg()
        if alg.private_key == None or alg.public_key == None:
            messagebox.showerror("Error", f"{alg_type} key not generated")
            return 

        docu_path = self.Document['path']
        if not docu_path:
            messagebox.showerror("Error", f"Document file not chosen")
            return

        sig = alg.sign(self.Document['value'])

        with open(f'{docu_path}_{alg_type}_sig.txt', "w") as sig_file:
            sig_file.write(",".join(map(str, sig)))

        messagebox.showinfo(
            "Document Signed", f"Document signed and signature saved as {docu_path}_{alg_type}_sig.txt"
        )

    def verify_document(self):
        alg_type, alg = self.get_alg()

        docu_path = self.Document['path']
        if not docu_path:
            messagebox.showerror("Error", f"Document file not chosen")
            return
        sig_path = self.Signature['path']
        if not sig_path:
            messagebox.showerror("Error", f"Signature file not chosen")
            return
        key_path = self.Foreign_key['path']
        if not key_path:
            messagebox.showerror("Error", f"Foreign public key file not chosen")
            return
        doc, sig, key = self.Document['value'],self.Signature['value'], self.Foreign_key['value']
        if (alg_type == "DSA" and len(key) == 3) or (alg_type == "el_gammal" and len(key) == 4):
            messagebox.showerror("Error", f"Incompatible {alg_type} key")
            return
        if alg.verify(doc, sig, key):
            messagebox.showinfo("Verification Successful", "The document signature is valid.")
        else:
            messagebox.showerror("Verification Failed", f"Invalid signature")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
