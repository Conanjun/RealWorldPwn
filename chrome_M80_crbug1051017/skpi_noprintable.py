import sys


if(len(sys.argv) != 3):
    print("python {0} inputfile outputfile".format(sys.argv[1]))
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

with open(input_file, "rb") as f:
    data = f.read()


res = ""

for ch in data:
    if (ord(ch) < 0x20 or ord(ch) == 0x7f):
    	print("find noprintable ch, replace it")
        ch = " "
    res += ch

with open(output_file, "wb") as f:
    f.write(res)

print("done")