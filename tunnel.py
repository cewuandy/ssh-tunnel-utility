import time

from kubernetes import client, config
import paramiko
import yaml
import sshtunnel

import atexit
import sys

server_list = []


def main():
    if len(sys.argv) != 2:
        print("Usage: python tunnel.py xxx.yaml")
        sys.exit(1)

    # Get the argument value
    argument = sys.argv[1]

    with open(argument, 'r') as file:
        # Load the YAML data from the file into a Python object
        config_yaml = yaml.safe_load(file)

    # Load the SSH config file
    ssh_config = paramiko.SSHConfig()
    ssh_config.parse(open(config_yaml['sshConfig'], 'r'))

    # Specify the SSH host name
    ssh_host = config_yaml['sshHost']
    # Get the SSH connection parameters for the specified host
    ssh_config_host = ssh_config.lookup(ssh_host)

    # Extract the connection parameters from the SSH config
    ssh_username = ssh_config_host.get('user')
    ssh_hostname = ssh_config_host.get('hostname')
    ssh_key_filename = ssh_config_host.get('identityfile')

    scp_kube_config(ssh_hostname, ssh_username, ssh_key_filename[0],
                    config_yaml['remoteKubeConfig'])

    # Load the Kubernetes configuration
    config.load_kube_config(config_file="kubeconfig")

    # Create a Kubernetes API client object
    api_client = client.CoreV1Api()

    create_ssh_tunnel(ssh_hostname, ssh_username, ssh_key_filename, 'localhost', 6443,
                      "localhost", 6443, "")

    # Iterate over the YAML object and print the values
    for item in config_yaml['tunnels']:
        local_host = item['local']['host']
        local_port = item['local']['port']
        remote_name = item['remote']['name']
        remote_namespace = item['remote']['namespace']
        remote_port = item['remote']['port']
        service = api_client.read_namespaced_service(name=remote_name, namespace=remote_namespace)
        create_ssh_tunnel(ssh_hostname, ssh_username, ssh_key_filename, local_host, local_port,
                          service.spec.cluster_ip, remote_port, remote_name)


def create_ssh_tunnel(ssh_hostname: str, ssh_username: str, ssh_key_filename: str,
                      local_ip: str, local_port: int, remote_ip: str, remote_port: int,
                      remote_name: str):
    server = sshtunnel.SSHTunnelForwarder(
        ssh_hostname,
        ssh_username=ssh_username,
        ssh_pkey=ssh_key_filename,
        ssh_private_key_password="secret",
        local_bind_address=(local_ip, local_port),
        remote_bind_address=(remote_ip, remote_port),
    )

    server.start()

    print(local_ip + ":" + str(local_port) + "\t<-\t" + remote_name + ":" + str(remote_port))
    server_list.append(server)


def scp_kube_config(hostname: str, username: str, private_key_path: str, remote_path):
    # Create an SSH client
    ssh_client = paramiko.SSHClient()

    # Automatically add the remote server's host key to the local host's key store
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Load the private key
    key = paramiko.RSAKey.from_private_key_file(private_key_path)

    # Connect to the remote server using the password
    ssh_client.connect(hostname=hostname, username=username, pkey=key)

    # Create an SCP client from the SSH client
    scp = ssh_client.open_sftp()

    # Copy the local file to the remote server
    scp.get(localpath='kubeconfig', remotepath=remote_path)

    # Close the SCP and SSH clients
    scp.close()
    ssh_client.close()


def exit_handler():
    for s in server_list:
        s.close()


if __name__ == '__main__':
    atexit.register(exit_handler)
    main()
    while 1:
        time.sleep(1)
