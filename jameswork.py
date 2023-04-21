import secrets
#import mysql.connector
#from mysql.connector import Error
import string
import hashlib
import base64
from tkinter import * 
import random
from Crypto.Cipher import AES
import pandas
from Crypto import Random

#mydb = mysql.connector.connect(insert connection string) connect to database
#mycursor = mydb.cursor()
#mycursor.execute("CREATE TABLE IF NOT EXISTS passwords(user VARCHAR(255), password VARCHAR(255))")
#sql = "INSERT INTO passwords(user, password) VALUES (%s, %s)"
#val = (username, encrypted_password)
#mycursor.execute(sql, val)
#mydb.commit()
global tk 
tk = Tk()
def UI():
    tk.title("Password Manager")
    tk.eval('tk::PlaceWindow . center')
    tk.geometry("400x400")
    username_entry = Entry(fg="black", bg="white", width=50)
    password_entry = Entry(fg="black", bg="white", width=50)
    button = Button(text="Submit", command= lambda: login(username_entry, password_entry))
    username_entry.pack()
    password_entry.pack()
    button.pack()

def createnew():
    top = Toplevel(tk)
    top.title('Generate Password')
    top.grab_set()
    options = [
        "Alphabetic Password",
        "Alphanumeric Password",
        "Special Character Password (suggested)"
    ]
    dropdown = StringVar(top)
    dropdown.set(options[0])

    select_option = OptionMenu(top, dropdown, *options)
    select_option.pack()
    label1 = Label(top, text="Please input desired length of password")
    entry = Entry(top, fg="black", bg="white", width=50)
    create = Button(top, text="Create", command= lambda: create_password())
    label1.pack()
    entry.pack()
    create.pack()
    def create_password():
        try:
            int_entry = int(entry.get())
            selection = dropdown.get()
            if selection == options[0]:
                letters = string.ascii_letters
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            elif selection == options[1]:
                letters = string.ascii_letters + string.digits
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            elif selection == options[2]:
                letters = string.ascii_letters + string.digits + string.punctuation
                generated_password = ''.join(secrets.choice(letters)for i in range(int_entry))
            display_pass = Label(top, text="Your generated password is " + generated_password)
            display_pass.pack()
            encrypted = encrypt(generated_password)
            display_encrypt = Label(top, text="This is now encrypted " + encrypted)
            display_encrypt.pack()
        except ValueError:
            error = Label(top, text="Please input an integer")
            if (error.winfo_exists()) == 0:
                error.pack()
        
    #letters = string.ascii_letters + string.digits + string.punctuation
    #generated_password = ''.join(secrets.choice(letters) for i in range(length))
def showall():
    #this will generate all passwords
    #sql = "SELECT password FROM passwords WHERE user = %s"
    #val = username
    #mycursor.execute(sql, val)
    #data = mycursor.fetchall()
    #for x in data:
    #   print(x)
    print("This will show all existing passwords")

def homepage():
    top = Toplevel(tk)
    top.title('Home Page')
    top.grab_set()
    home = Label(top, text="Hello!")
    create_password = Button(top, text="Create a new password", command=createnew)
    see_passwords = Button(top, text="See existing passwords", command=showall)
    home.pack()
    create_password.pack()

#def read_from_file():
    #data = pandas.read_excel('C:\Users\evaan\Dropbox\PC\Documents\PasswordManagerFile.xlsx')
    #data_format = pandas.DataFrame(data, columns=['name'])
    #display = Label(text=data_format)
    #print(display)

#def write_to_file():
    #data_formatted = ""
    #with pandas.ExcelWriter('C:\Users\evaan\Dropbox\PC\Documents\PasswordManagerFile.xlsx', mode='a') as writer:
        #data_formatted.to_excel(writer, sheet_name='Sheet1')


def encrypt(data):
    #block_size = 16
    #pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)
    #unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    #password = input("Enter encryption password: ")

    #private_key = hashlib.sha256(password.encode("utf-8")).digest()
    #raw = pad(raw)
    #iv = Random.new().read(AES.block_size)
    #cipher =   AES.new(private_key, AES.MODE_CBC, iv)
    key = "xxx".encode("utf8")
    cipher = AES.new(key, AES.MODE_EAX)
    data = data.encode("utf8")
    #this is being fucked up somewhere
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    ciphertext = str(ciphertext)
    print(ciphertext)
    return ciphertext
    #this encrypts data, need to replace variable data

def decrypt():
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

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