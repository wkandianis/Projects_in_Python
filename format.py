import json

filename = input("enter filename: ")
f = open("format.txt", "w")
with open(filename) as x:
    data = json.load(x)
    for p in data['partners']:
        f.write('firstName: ' + p['firstName'])
        f.write('lastName: ' + p['lastName'])
        f.write('email: ' + p['email'])
        f.write('country: ' + p['country'])
        dates = p['availableDates']
        f.write('availableDates' + ': [')
        for d in dates:
            f.write(d) 
      
f.close()    