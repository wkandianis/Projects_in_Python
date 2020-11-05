import requests
import mechanize

# take input from the user
url = input("Enter url: ")
filename = input('Enter file name: ')
# open file and assign individual lines to data
file = open(filename, 'r')
data = file.readlines()

# line takes each line in data
for line in data:
    # adds the injection to the url, sets it to injection variable
    injection = (url + line)
    # gets the response from the url with the injections
    response = requests.get(injection)
    # checks to see if the injected code is in the response text
    if line in response.text:
        print('XSS Vulnerability Found')
        

# close file
file.close()

