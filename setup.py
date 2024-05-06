import pexpect
import time

def run_command(process, command, prompt=r'\$'):
    print(f"Sending command: {command}")
    process.sendline(command)
    process.expect(prompt)
    output = process.before.decode().strip()  # Decode from bytes to string, strip whitespace
    print(f"Output from command '{command}':\n{output}")

def main():
    # Start Bash processes with a longer timeout for Minikube commands
    bash = pexpect.spawn('/usr/bin/env bash', timeout=300)
    fileShare = pexpect.spawn('/usr/bin/env bash', timeout=300)
    minikubeSSH = pexpect.spawn('minikube ssh', timeout=300)

    # Run minikube delete
    #bash.expect(r'\$')
    #run_command(bash, 'minikube delete')

    # Start Minikube
    #run_command(bash, 'minikube start')

    # Read in the file
    with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'r') as file:
        filedata = file.read()

    # Replace the target string
    filedata = filedata.replace('tc_egress', 'tc_egress1')
    filedata = filedata.replace('middleware', 'database')

    # Write the file out again
    with open('./libbpf-bootstrap/examples/c/tcE.bpf.c', 'w') as file:
        file.write(filedata)

    # Expect the specific SSH prompt
    #minikubeSSH.expect(r'docker@minikube:~\$')

    #appPath = 'host/Documents/StatTrek'
    #appRegex = r'docker@minikube:/host/Documents/StatTrek\$'
    #bpfPath = 'host/Documents/StatTrek/libbpf-bootstrap/examples/c'
    #bpfRegex = r'docker@minikube:/host/Documents/StatTrek/libbpf-bootstrap/examples/c\$'

    # Command execution
    # Assuming the path you're accessing is correctly relative to the SSH user's home directory
    #run_command(minikubeSSH, f'cd ../../{appPath}', prompt=appRegex)
    #run_command(minikubeSSH, f'python3 interfaces.py', prompt=appRegex)
    #run_command(minikubeSSH, f'cd ../../{bpfPath}', prompt=bpfRegex)
    #run_command(minikubeSSH, 'ls', prompt=bpfRegex)
    #run_command(minikubeSSH, './tcE')



if __name__ == "__main__":
    main()