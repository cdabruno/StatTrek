import pexpect
import time
import re
import sys

def run_command(process, command, prompt=r'\$'):
    print(f"Sending command: {command}")
    process.sendline(command)
    process.expect(prompt)
    output = process.before.decode().strip()  # Decode from bytes to string, strip whitespace
    print(f"Output from command '{command}':\n{output}")
    return output

def main():

    args = sys.argv[1:]

    # Start Bash processes with a longer timeout for Minikube commands
    bash = pexpect.spawn('/usr/bin/env bash', timeout=300)
    fileShare = pexpect.spawn('/usr/bin/env bash', timeout=300)
    minikubeSSH = pexpect.spawn('minikube ssh', timeout=300)

    # Run minikube delete
    #bash.expect(r'\$')
    #run_command(bash, 'minikube delete')

    # Start Minikube
    #run_command(bash, 'minikube start')


    # Expect the specific SSH prompt
    minikubeSSH.expect(r'docker@minikube:~\$')

    appPath = 'host/Documents/StatTrek'
    appRegex = r'docker@minikube:/host/Documents/StatTrek\$'
    bpfPath = 'host/Documents/StatTrek/libbpf-bootstrap/examples/c'
    bpfRegex = r'docker@minikube:/host/Documents/StatTrek/libbpf-bootstrap/examples/c\$'

    # Command execution
    # Assuming the path you're accessing is correctly relative to the SSH user's home directory
    run_command(minikubeSSH, f'cd ../../{appPath}', prompt=appRegex)
    interfaces = run_command(minikubeSSH, f'python3 interfaces.py', prompt=appRegex)

    middlewareInterface = interfaces.split()[4]
    databaseInterface = interfaces.split()[6]

    # database

    if(args[0] == 'database'):

        run_command(bash, 'rm ./libbpf-bootstrap/examples/c/tcI -f')
        run_command(bash, 'rm ./libbpf-bootstrap/examples/c/tcE -f')

        # ebpf

        with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'r') as file:
            filedata = file.read()
        
        filedata = filedata.replace('tc_egress(', 'tc_egress1(')
        filedata = filedata.replace('middleware', 'database')

        
        with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'w') as file:
            file.write(filedata)

        with open('./libbpf-bootstrap/examples/c/tcI.bpf.c', 'r') as file:
            filedata = file.read()

        filedata = filedata.replace('tc_ingress(', 'tc_ingress1(')
        filedata = filedata.replace('middleware', 'database')

        with open('./libbpf-bootstrap/examples/c/tcI.bpf.c', 'w') as file:
            file.write(filedata)

        #libbpf

        with open('./libbpf-bootstrap/examples/c/tcE.c', 'r') as file:
            filedata = file.read()
        
        filedata = re.sub(r'#define LO_IFINDEX [0-9]+', '#define LO_IFINDEX ' + databaseInterface, filedata)
        filedata = filedata.replace('tc_egress)', 'tc_egress1)')

        
        with open('./libbpf-bootstrap/examples/c/tcE.c', 'w') as file:
            file.write(filedata)

        with open('./libbpf-bootstrap/examples/c/tcI.c', 'r') as file:
            filedata = file.read()

        filedata = re.sub(r'#define LO_IFINDEX [0-9]+', '#define LO_IFINDEX ' + databaseInterface, filedata)
        filedata = filedata.replace('tc_ingress)', 'tc_ingress1)')

        with open('./libbpf-bootstrap/examples/c/tcI.c', 'w') as file:
            file.write(filedata)

    if(args[0] == 'middleware'):

        run_command(bash, 'rm ./libbpf-bootstrap/examples/c/tcI -f')
        run_command(bash, 'rm ./libbpf-bootstrap/examples/c/tcE -f')

        # ebpf

        with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'r') as file:
            filedata = file.read()
        
        filedata = filedata.replace('tc_egress1(', 'tc_egress(')
        filedata = filedata.replace('database', 'middleware')

        
        with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'w') as file:
            file.write(filedata)

        with open('./libbpf-bootstrap/examples/c/tcI.bpf.c', 'r') as file:
            filedata = file.read()

        filedata = filedata.replace('tc_ingress1(', 'tc_ingress(')
        filedata = filedata.replace('database', 'middleware')

        with open('./libbpf-bootstrap/examples/c/tcI.bpf.c', 'w') as file:
            file.write(filedata)

        #libbpf

        with open('./libbpf-bootstrap/examples/c/tcE.c', 'r') as file:
            filedata = file.read()
        
        filedata = re.sub(r'#define LO_IFINDEX [0-9]+', '#define LO_IFINDEX ' + middlewareInterface, filedata)
        filedata = filedata.replace('tc_egress1)', 'tc_egress)')

        
        with open('./libbpf-bootstrap/examples/c/tcE.c', 'w') as file:
            file.write(filedata)

        with open('./libbpf-bootstrap/examples/c/tcI.c', 'r') as file:
            filedata = file.read()

        filedata = re.sub(r'#define LO_IFINDEX [0-9]+', '#define LO_IFINDEX ' + middlewareInterface, filedata)
        filedata = filedata.replace('tc_ingress1)', 'tc_ingress)')

        with open('./libbpf-bootstrap/examples/c/tcI.c', 'w') as file:
            file.write(filedata)




    


    
    #run_command(minikubeSSH, f'cd ../../{bpfPath}', prompt=bpfRegex)
    #run_command(minikubeSSH, 'ls', prompt=bpfRegex)
    #run_command(minikubeSSH, './tcE')



if __name__ == "__main__":
    main()