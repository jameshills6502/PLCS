import secrets
import mysql.connector
from mysql.connector import Error, connect
import string
import hashlib
import base64
from tkinter import * 
import random
from Crypto.Cipher import AES
mydb = mysql.connector.connect(host ="localhost", db ="passwordmanager", user="applogin", password="applogin")
mycursor = mydb.cursor()
#CREATE USER 'applogin' IDENTIFIED BY 'applogin';
#GRANT ALL ON `passwordmanager`.* TO 'applogin';
#potentially add a description per password, allows user to remember pass
#CREATE TABLE IF NOT EXISTS `passwordmanager`.`passwords` (
# 'password_id' INT NOT NULL AUTO_INCREMENT, 
# `user_id` INT NOT NULL,
#  `password` VARCHAR(255) NULL,
#  PRIMARY KEY (`password_id));
#CREATE TABLE IF NOT EXISTS `passwordmanager`.`users` (
#  `user_id` INT NOT NULL AUTO_INCREMENT,
#  `username` VARCHAR(255) NULL,
#  `password` VARCHAR(255) NULL,
#  PRIMARY KEY (`user_id`));
global tk 
tk = Tk()
def UI():
    tk.title("Password Manager")
    tk.eval('tk::PlaceWindow . center')
    tk.geometry("400x400")
    l1 = Label(tk, text="Enter Username:")
    l2 = Label(tk, text="Enter Password:")
    username_entry = Entry(tk, fg="black", bg="white", width=50)
    password_entry = Entry(tk, fg="black", bg="white", width=50)
    button = Button(tk, text="Login", command= lambda: login(username_entry, password_entry))
    button2 = Button(tk, text="Create Account", command=createaccount)
    l1.grid(row=0,column=0,sticky=W,pady=2)
    l2.grid(row=1, column=0, sticky=W, pady=2)
    username_entry.grid(row=0, column=1, pady=2)
    password_entry.grid(row=1, column=1,pady=2)
    button.grid(row=2, column=1, pady=1)
    button2.grid(row=2, column=0, sticky=W, pady=2)
def createaccount():
    top = Toplevel()
    top.title('Create Account')
    top.grab_set()
    l1 = Label(top, text="Enter Username:")
    l2 = Label(top, text="Enter Password:")
    l3 = Label(top, text="Confirm Password:")
    username = Entry(top, fg="black", bg="white", width=50)
    password = Entry(top, fg="black", bg="white", width=50)
    confirmpass = Entry(top, fg="black", bg="white", width=50)
    submit = Button(top, text="Create Account", command= lambda: storenewacc(top, username, password, confirmpass))
    l1.grid(row=0,column=0,sticky=W, pady=2)
    l2.grid(row=1, column=0, sticky=W, pady=2)
    l3.grid(row=2, column=0, sticky=W, pady=2)
    username.grid(row=0, column=1, pady=2)
    password.grid(row=1, column=1, pady=2)
    confirmpass.grid(row=2, column=1, pady=2)
    submit.grid(row=3, column=1, pady=1)

def storenewacc(top, usernamewidget, passwordwidget, confirmpasswidget):
    username = usernamewidget.get()
    password = passwordwidget.get()
    confirmpass = confirmpasswidget.get()
    if password != confirmpass:
        error = Label(top, text="Passwords don't match!")
        error.grid(row=4, column=1, pady=1)
    else:
        sql1 = "SELECT * FROM users WHERE username = %s;"
        val = (username, )
        mycursor.execute(sql1, val)
        data = mycursor.fetchall()
        if len(data) > 0:
            error = Label(text="Account already exists!")
            error.grid(row=4, column=1, pady=1)
        else:
            sql = "INSERT INTO users(username, password) VALUES(%s, %s)"
            val = (username, password)
            mycursor.execute(sql, val)
            mydb.commit()
            print("Data uploaded!")
            top.destroy()

def createnew(user_id):
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
    select_option.grid(row=0, column=0, sticky=W, pady=2)
    label1 = Label(top, text="Please input desired length of password")
    entry = Entry(top, fg="black", bg="white", width=50)
    create = Button(top, text="Create", command= lambda: create_password(top, dropdown, entry, options, user_id))
    label1.grid(row=1, column=0, sticky=W,pady=2)
    entry.grid(row=2, column=0, sticky=W, pady=2)
    create.grid(row=4, column=0, sticky=W, pady=2)
def create_password(top, dropdown, entry, options, user_id):
        #this function generates a password and allows the user
        #to save it to the database using the save button
        #user can also copy directly to clipboard
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
            copy = Button(top, text="Copy", command= lambda: copytoclip(generated_password, top))
            copy.grid(row=1, column=1, pady=1)
            savepass = Button(top, text="Save Password", command = lambda: savepassword(generated_password, user_id))
            savepass.grid(row=1,column=2, pady=1)
            display_pass = Label(top, text="Your generated password is " + generated_password)
            #make it so that if the button is clicked again, the label
            #gets reset so drop and grid it
            display_pass.grid(row=0, column=1, pady=1)
        except ValueError:
            error = Label(top, text="Please input an integer")
            if (error.winfo_exists()) == 1:
                error.grid(row=3, column=0, sticky=W, pady=2)

def copytoclip(password, top):
     top.withdraw
     top.clipboard_clear()
     top.clipboard_append(password)
     top.update() 
def savepassword(generated_password, user_id):
    #saves the password to the database
    #encrypted = encrypt(generated_password)
    #print(encrypted)
    sql = "INSERT INTO passwords(user_id, password) VALUES(%s, %s);"
    #currently doesn't work as primary key is needed 
    #in passwords table
    var = (user_id, generated_password)
    mycursor.execute(sql, var)
    mydb.commit()

def showall(user_id):
    #this will generate all passwords
    top = Toplevel()
    top.title("Passwords")
    top.grab_set()
    l1 = Label(top, text="Your stored passwords:")
    l1.grid(row=0, column=0, sticky=W, pady=2)
    sql = "SELECT password FROM passwords WHERE user_id = %s;"
    var = (user_id, )
    mycursor.execute(sql, var)
    data = mycursor.fetchall()
    for x in data:
        loop = 1
        for i in data:
            password = i
            label = Label(top, text=password)
            number = Label(top, text=loop)
            number.grid(row=loop,column=0, sticky=W, pady=2)
            label.grid(row=loop, column=1, sticky=W, pady=2)
            copy = Button(top, text="Copy", command= lambda: copytoclip(password, top))
            copy.grid(row=loop, column=2, pady=1)
            delete = Button(top, text="Delete Password", command= lambda: deletepassword(password)) # command should delete the password from the database
            delete.grid(row=loop, column=3, pady=1)
            loop += loop
def deletepassword(password, ):
    sql = "DELETE password FROM passwords WHERE password = %s;"
    var = (password, )
    mycursor.execute(sql, var)
    mydb.commit()
#this doesn't work just yet!
def homepage(user_id):
    top = Toplevel(tk)
    top.title('Home Page')
    top.grab_set()
    home = Label(top, text="Hello!")
    create_password = Button(top, text="Create a new password", command= lambda: createnew(user_id))
    see_passwords = Button(top, text="See existing passwords", command= lambda: showall(user_id))
    home.pack()
    create_password.pack()
    see_passwords.pack()

def encrypt(data):
    #block_size = 16
    #pad = lambda s: s + (block_size - len(s) % block_size) * chr(block_size - len(s) % block_size)
    #unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    #password = input("Enter encryption password: ")

    #private_key = hashlib.sha256(password.encode("utf-8")).digest()
    #raw = pad(raw)
    #iv = Random.new().read(AES.block_size)
    #cipher =   AES.new(private_key, AES.MODE_CBC, iv)
    #data needs to be converted to bytes in order to be hashed
    print("Cipher has been called")
    key = "xxx".encode("utf-8")
    cipher = AES.new(key, AES.MODE_EAX)
    #here the data is being encoded
    data = data.encode("utf-8")
    #here the data is being decoded
    #data = data.decode("utf-8")

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
    sql = "SELECT * FROM users WHERE username = %s;"
    val = (username, )
    mycursor.execute(sql, val)
    data = mycursor.fetchall()
    if len(data) != 0:
        for x in data:
            loop = 0
            for i in x:
                if loop == 0:
                    user_id = i
                elif loop == 2:
                    stored_password = i
                    #need to hash passwords when stored and decrypt after
                    #pulling
                loop += 1
        if password != stored_password:
            error = Label(text="Wrong username or password")
            error.grid_forget()
            presence_check = error.winfo_exists()
            if presence_check == 1:
                error.grid(row=3,column=1,pady=1)
        elif password == stored_password:
            homepage(user_id)
    if len(data) == 0:
        error = Label(text="Wrong username or password")
        error.grid_forget()
        presence_check = error.winfo_exists()
        if presence_check == 1:
            error.grid(row=3,column=1,pady=1) 
UI()
tk.mainloop()
mydb.close()