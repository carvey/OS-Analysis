import sys
import os
import requests
import re

from collections import defaultdict
from bs4 import BeautifulSoup

# echo "PATH=\$PATH:~/.local/bin" >> ~/.bashrc
# easy_install --user pip
# pip install --user requests

# or install pip with
# wget https://raw.github.com/pypa/pip/master/contrib/get-pip.py && python get-pip.py --user

in_file_path = "dumps/%s" % os.path.basename(sys.argv[1])
in_file = open(in_file_path, 'r')

out_file_path = "data/%s" % os.path.basename(sys.argv[1])
out_file = open(out_file_path, 'w')

procs = {} 
procs_count = {}
proc_errs = {}
sec_rating = {}

for line in in_file:
    line = line.rstrip().lower()
    desc = ""

    if ".exe" not in line:
        line += ".exe"

    if line == "wininit.exe":
        continue

    # if the line is already in procs, dont request again
    if line not in procs:
        url = "https://www.file.net/process/%s.html" % line
        page = requests.get(url)

        # only try and parse the page if successful request
        if page.status_code == 200:
            soup = BeautifulSoup(page.text, "html.parser")

            # get description above the picture
            for para in soup.find(id="GreyBox").find_all("p"):

                # don't get ad
                if not para.find(text=re.compile("Click to Run a Free")):

                    # don't get exe wanting
                    if not para.find(text=re.compile("exe extension on a")):
                        if desc:
                            desc += "\n\n"

                        desc += str(para.text)

            additional_desc = soup.find(itemprop="description").parent.text
            additional_desc = additional_desc.replace("\n", "\n\n")
            
            if desc:
                desc += "\n\n"

            if additional_desc[0:25] != desc[0:25]:
                desc += additional_desc
             

            rating = re.findall(r'\d+% dangerous', desc)
            if rating:
                rating = re.findall(r'\d+%', rating[0])[0]
                sec_rating[line] = rating


        url2 = "https://www.neuber.com/taskmanager/process/%s.html" % line
        page2 = requests.get(url2)
        print("%s: %s" % (line, page2.status_code))
        if page2.status_code == 200:
            soup = BeautifulSoup(page2.text, "html.parser")

            content = soup.find(id="content").find_all("br")[3].next_sibling.next_sibling.text
            if desc:
                desc += "\n\n"

            desc += content
            print(desc)

        if page.status_code != 200 and page2.status_code != 200:
            proc_errs[line] = page.status_code

        if desc:
            procs[line] = desc

    if line in procs_count:
        procs_count[line] += 1
    else:
        procs_count[line] = 1


# file header
out_file.write("ANALYSIS OF: %s\n--------------------------------\n" % os.path.basename(in_file_path))

# attributes section
out_file.write("ATTRIBUTES:\n\n")
out_file.write("Processes: %s\n" %  len(procs))
out_file.write("Retrieval Errors: %s\n" % len(proc_errs))
# high_ratings = {k:v for k:v in sec_rating.iteritems() if v >}
# out_file.write("Technical Security Ratings above 50%: %s\n", high_ratings)
out_file.write("\n--------------------------------\n")

# error section
out_file.write("RETRIEVAL ERRORS:\n\n")
for proc, error_code in proc_errs.items():
    out_file.write("%s: %s\n" % (proc, error_code))
out_file.write("\n--------------------------------\n")

# plain service section
out_file.write("SERVICE LIST:\n\n")
for proc, description in procs.items():
    rating = ""
    if sec_rating.get(proc):
        rating = "(%s)" % sec_rating.get(proc) 
    out_file.write("%s %s\n" % (proc, rating))

out_file.write("\n--------------------------------\n")

# process descriptions
out_file.write("PROCESS DESCRIPTIONS\n\n")
for proc, description in procs.items():

    out_file.write("\nProcess: %s\n" % proc)
    out_file.write("Count: %s\n" % procs_count[proc])
    if sec_rating.get(proc):
        out_file.write("Technical Security Rating: %s\n\n" % sec_rating[proc])
    else:
        out_file.write("\n")
    out_file.write(description)
    out_file.write("\n\n----------------\n")

in_file.close()
out_file.close()

