import sys

with open(sys.argv[1], 'rb') as f:
    blob=', '.join(str(int(c)) for c in f.read())
    print(f"""package main

var BiffBlob = []byte{{{blob}}}

""")
