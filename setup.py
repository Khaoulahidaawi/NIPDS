import subprocess
import sys
import os

os.system('cls')
reqs = subprocess.check_output([sys.executable, '-m', 'pip', 'freeze'])
installed_packages = [r.decode().split('==')[0] for r in reqs.split()]
packages = ['time', 'datetime', 'socket', 'icmplib', 'pyshark', 'psutil', 'pyfiglet', 'random', 'termcolor', 'colorama' , 'scapy']

for pkg in packages:
    if(pkg in installed_packages):
        print(pkg + " already installed.")
    else:
        os.system("pip install "+pkg)
