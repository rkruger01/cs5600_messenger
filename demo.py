# we use tkinter to help us with GUI
from tkinter import *
# we use re to help with some regex
import re

#special characters are used for username and password checking
special_characters = re.compile('[ ,.?@!#$%^&*()<>?/\|}{~:]')

# This is the list of users, currently will contain usernames and passwords
user_list = []

#Grabbing the user information from the lists
user_temp = 0
# open the file of user information to put it into the user_list
user_file = open('list.txt','r')
# each user will have a username and password
for users in user_file:
    # split the username and password with a comma
    user_entries = users.split(",")
    user_list.append(user_entries)
    # get rid of the newline character at the end of each password
    user_list[user_temp][1] = user_list[user_temp][1].rstrip("\n")
    # iterate through the file until there is no more users
    user_temp = user_temp + 1
# close the file
user_file.close()

# this function sends the user_list to the list to the user_file
def user_update():
    #write to the file
    output_file = open('list.txt', 'w')
    for x in range(len(user_list)):
        for y in range(len(user_list[x])):
            output_file.write(user_list[x][y])
            # add a comma between entries unless it is the last element for the user
            if y != (len(user_list[x]) - 1):
                output_file.write(',')
        # add a new line for every user's information
        output_file.write('\n')
    # close the file
    output_file.close()
    pass

# create root main window, it will be used as the login window
root = Tk()
root.title('EasyChat Login')

# include the text boxes for username and password
input_username = Entry(root, width=50)
input_password = Entry(root, width=50)

# create the Labels for the username and password
user_label = Label(root, text="Enter your username:")
password_label = Label(root, text="Enter your password:")

# blank label is used for error text
blank_label = Label(root, text = " ")


# place the the labels and entry boxes
user_label.grid(row=0, column=0)
password_label.grid(row=1, column=0)
input_username.grid(row=0, column=1)
input_password.grid(row=1, column=1)
blank_label.grid(row=3, column=0, columnspan=2)


# this function is used to help create users by checking a and b
def create_user_inputs(a,b):
    # open a new window to help create users
    new_user_window = Tk()
    # error text in case something goes wrong
    error_text = ""
    # label2 is there to help with error text
    #my_label2 = Label(new_user_window, text="                                                 ")
    #my_label2.grid(row=0, column=0, columnspan=2)

    #index is used to check if a user exists
    index = -1
    #if the username inputted is already a username, update the index
    for number in range(len(user_list)):
        if user_list[number][0] == a:
            index = number
    #if the index does not update, it might be a valid username
    if index == -1:
        #check to see if username has any special characters
        if (special_characters.search(a) == None):
            #check to see if password has any special characters
            if (special_characters.search(b) == None):
                # check to see the length of username is in range
                if(len(a) >= 7 and len(a) < 21):
                    # check to see the length of password is in range
                    if (len(b) >= 7 and len(b) < 21):
                        # if successful, send a message window with the notice that you created the user
                        error_text = "Creating New User, " + a
                        new_user = [a,b]
                        #add valid user to list of users and update file of users
                        user_list.append(new_user)
                        user_update()
                    else:
                        error_text = "Password must between 7 and 20 characters long."
                else:
                    error_text = "Username must between 7 and 20 characters long."
            else:
                error_text = "Password cannot contain special characters"
        else:
            error_text = "Username cannot contain special characters"
    else:
        error_text = "Username, " + a + " , is already being used"
    #place message in the new_window
    my_label = Label(new_user_window, text=error_text)
    my_label.grid(row=0, column=0, columnspan=2)
    #add a close button so the user can leave if so desired
    close_window = Button(new_user_window, text="Close Window", command=new_user_window.destroy)
    close_window.grid(row=1, column=0, columnspan=2)
    pass

# this function is used to check if usernames and passwords are allowed for login
def check_inputs():
    # text for any failures of a login
    error_text = ""

    # blank label reset
    my_label2 = Label(root, text="                                                 ")
    my_label2.grid(row=3, column=0, columnspan=2)

    # finding a username in the list
    index = -1
    for number in range(len(user_list)):
        if user_list[number][0] == input_username.get():
            index = number

    # if the username is in the username list, continue
    if index != -1:
        # if the username has the corresponding password, open the chatroom for that particular user
        if input_password.get() == user_list[index][1]:
            # open the chatroom for this specific user
            open_chatroom(user_list[index][0])
            error_text = "                                                 "
            # reset the inputs for username and password
            input_username.delete(0, 'end')
            input_password.delete(0, 'end')
            #destory the last error label
            my_label2.destroy()
        else:
            # the password is incorrect,
            error_text = " This password is incorrect"
            # reset the inputs for username and password
            input_username.delete(0, 'end')
            input_password.delete(0, 'end')
    else:
        # the username is incorrect
        error_text = "This username does not exist"
        # reset the inputs for username and password
        input_username.delete(0, 'end')
        input_password.delete(0, 'end')
    # output the error label
    my_label = Label(root, text=error_text)
    my_label.grid(row=3, column=0, columnspan=2)
    pass

# this function opens the chatroom window
def open_chatroom(username_text):
    # this function is used to output messages to the chatroom window
    def message_output(username_text, input_text):
        message_text = username_text + ": " + input_text
        listbox.insert(END, message_text)
        pass

    # new chatroom window
    chatroom = Tk()
    chatroom.title('EasyChat Chatroom')

    # a frame to contain the listbox, which is what we use for the chatroom
    chat_frame = Frame(master=chatroom, width=100, height=200, bg="red")
    # a vertical scroll bar for the chatroom messages
    scrollbar = Scrollbar(chat_frame)
    scrollbar.pack(side=RIGHT, fill=Y)
    # the listbox used for the chatroom
    listbox = Listbox(chatroom, bd=0, yscrollcommand=scrollbar.set, width=100)
    listbox.pack(fill=X)

    # place the messages box/chatroom box
    chat_frame.grid(row=0, column=0, columnspan=2)
    # make a input box for messages
    message_input = Entry(chatroom, width=50)
    # button that updates the messages to either include usernames or commands
    message_button = Button(chatroom, text="Enter your message", command=lambda: message_output(username_text,message_input.get()))
    # place message button and input
    message_input.grid(row=1, column=0)
    message_button.grid(row=1, column=1)
    # set the scroll bar to the list box
    listbox.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=listbox.yview)
    pass

#this function is meant to help users to create their own user
def create_user():
    #user window for creating users
    user_window = Tk()
    # create temp entry boxes
    create_username = Entry(user_window, width=50)
    create_password = Entry(user_window, width=50)

    # create labels to say enter info
    new_user_label = Label(user_window, text="Enter your new username:")
    new_password_label = Label(user_window, text="Enter your new password:")
    # this button calls upon the create_user_inputs functions with the input entries
    new_submit_button = Button(user_window, text="Create a New User", command=lambda: create_user_inputs(create_username.get(),create_password.get()))
    blank_label = Label(user_window, text="")

    # place the usernames and password stuff
    new_user_label.grid(row=0, column=0)
    new_password_label.grid(row=1, column=0)
    create_username.grid(row=0, column=1)
    create_password.grid(row=1, column=1)
    new_submit_button.grid(row=2, column=0, columnspan=2)
    blank_label.grid(row=3, column=0, columnspan=2)
    # close window
    close_window = Button(user_window, text="Close Window", command=user_window.destroy)
    close_window.grid(row=4, column=0, columnspan=2)
    pass


# create buttons for the login window
submit_button = Button(root, text="Login in", command=check_inputs)
create_user_button = Button(root, text="Create User", command=create_user)
# place buttons for the login window
submit_button.grid(row=2, column=0, columnspan=2)
create_user_button.grid(row=4, column=0, columnspan=2)

# update the user_file just in case in case
user_update()

# this is used to loop the main window
mainloop()
