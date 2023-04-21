from tkinter import * 
import random
from pandas import *
from string import *
from secrets import *
#from Crypto.Cipher import AES
#from Crypto.Cipher import random


global tk 
tk = Tk()
def UI():
    tk.title("Password Manager")
    username_entry = Entry(fg="black", bg="white", width=50)
    password_entry = Entry(fg="black", bg="white", width=50)
    button = Button(text="Submit", command= lambda: login(username_entry, password_entry))
    username_entry.pack()
    password_entry.pack()
    button.pack()

def createnew():
    top = Toplevel()
    top.title('Generate Password')
    options = [
        "Alphabetic Password",
        "Alphanumeric Password",
        "Special Character Password (suggested)"
    ]
    dropdown = StringVar(top)
    dropdown.set(options[0])

    select_option = OptionMenu(top, dropdown, *options)
    select_option.pack()
    label1 = Label(text="Please input desired length of password")
    entry = Entry(fg="black", bg="white", width=50)
    create = Button(text="Create", command= lambda: create_password())
    def create_password():
        try:
            int_entry = int(entry.get())
            selection = dropdown.get()
            if selection == options[0]:
                letters = string.ascii_letters
                generated_password = ''.join(secrets.choice(letters)for i in range(length))
            elif selection == options[1]:
                letters = string.ascii_letters + string.digits
                generated_password = ''.join(secrets.choice(letters)for i in range(length))
            elif selection == options[2]:
                letters = string.ascii_letters + string.digits + string.punctuation
                generated_password = ''.join(secrets.choice(letters)for i in range(length))
            display_pass = Label(text="Your generated password is " + generated_password)
            display_pass.pack()
        except ValueError:
            error = Label("Please input an integer")
            if (error.winfo_exists()) == 0:
                error.pack()
        
    #letters = string.ascii_letters + string.digits + string.punctuation
    #generated_password = ''.join(secrets.choice(letters) for i in range(length))


def homepage():
    top = Toplevel()
    top.title('Home Page')
    home = Label(text="Hello!")
    create_password = Button(text="Create a new password", command=createnew)
    see_passwords = Button()
    home.pack()

def write_to_file():
    data = pd.read_excel(r'C:\Users\root')


#def encrypt():
    #key = b'Sixteen byte key'
    #cipher = AES.new(key, AES.MODE_EAX)

    #nonce = cipher.nonce
    #ciphertext, tag = cipher.encrypt_and_digest(data)
    #this encrypts data, need to replace variable data

#def decrypt():
    #cipher = AES.new(key, AES.MODE_EAX, nonce)
    #data = cipher.decrypt_and_verify(ciphertext, tag)
def login(username_entry, password_entry):
    username = username_entry.get()
    password = password_entry.get()
    stored_username = "J"
    stored_password = "H"
    if username != stored_username or password != stored_password:
        error = Label(text="Wrong username or password, you entered " + username + password)
        presence_check = error.winfo_exists()
        if presence_check == 0:
            error.pack()
            username_entry.delete(0, tk.END)
            password_entry.delete(0, tk.END)
    else:
        right = Label(text="Correct")
        right.pack()
        homepage()
UI()
tk.mainloop()