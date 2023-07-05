# HostInspector

Python script to identify "interesting hosts" from initial Nmap discovery scans.

## Usage

Usage is self-explanatory, provide nmap .xml output, choose a sorting mode and specifiy how many hosts to return.

```
usage: HostInspector.py [-h] -f XMLFILE -m {simple,smart} -c COUNT -o OUTFILE

options:
  -h, --help            show this help message and exit
  -f XMLFILE, --xmlfile XMLFILE
                        Nmap XML file to parse
  -m {simple,smart}, --mode {simple,smart}
                        Host sorting mode
  -c COUNT, --count COUNT
                        Number of hosts to return
  -o OUTFILE, --outfile OUTFILE
                        Outputfile name
```
