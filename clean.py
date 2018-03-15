import sys
import fileinput

for i, line in enumerate(fileinput.input(sys.argv[1], inplace=1)):
    words = line.split(" ")
    proc = words[int(sys.argv[2])]
    if (proc.isdigit()):
        proc = words[int(sys.argv[2]) + 1]
    print(proc)
