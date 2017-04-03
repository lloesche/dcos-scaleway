#!/usr/bin/env python3
from scaleway.apis import ComputeAPI
from scaleway.apis import AccountAPI
import slumber.exceptions
import logging
import argparse
import sys
import os
import uuid
import time
import atexit
import requests
import os.path
import stat
import yaml
import subprocess
import socket
import shutil
from multiprocessing.pool import ThreadPool
from retrying import retry
from pprint import pprint

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('DCOSInstall').setLevel(log_level)
logging.getLogger('ScalewayInstances').setLevel(log_level)
log = logging.getLogger(__name__)


def main(argv):
    p = argparse.ArgumentParser(description='Install DC/OS on Scaleway')
    p = DCOSInstall.add_args(p)
    p = ScalewayInstances.add_args(p)
    args = p.parse_args(argv)
#    print("XXX CREATING SERVER")
#    server = swi.create_server('master1', swi.images['CentOS 7 (beta)']['id'], 'c2s', {})
#    pprint(server)
#    print("XXX POWERING ON SERVER")
#    pprint(swi.poweron_server(server['id']))
#    print("XXX GETTING SERVER STATE")
#    pprint(swi.server(server['id']))
#    print("XXX POWERING OFF SERVER")
#    pprint(swi.poweroff_server(server['id']))
#    print("XXX DELETING SERVER")
#    pprint(swi.delete_server(server['id']))
#    print("XXX DELETING VOLUMES")
#    for volume in server['volumes'].values():
#        pprint(swi.delete_volume(volume['id']))
#    #pprint(swi._api.query().servers().get())
    dcos = DCOSInstall(args, ScalewayInstances(args))
    dcos.deploy()

    if args.cleanup:
        input('Press Enter to DESTROY all instances...')
        if not args.errclnup:
            dcos.oi.cleanup()
    else:
        if args.errclnup:
            atexit.unregister(dcos.oi.cleanup)
    sys.exit(0)


class DCOSInstall:
    def __init__(self, args, swi):
        self.log = logging.getLogger(self.__class__.__name__)
        self.args = args
        self.swi = swi
        self.masters = []
        self.agents = []
        self.pubagents = []
        self.installer = 'dcos_generate_config.sh'
        self.dcos_config = {
            'bootstrap_url': 'file:///opt/dcos_install_tmp',
            'cluster_name': 'Scaleway Test',
            'exhibitor_storage_backend': 'static',
            'master_discovery': 'static',
            'security': self.args.security,
            'process_timeout': 10000,
            'resolvers': ['8.8.8.8', '8.8.4.4'],
            'ssh_port': self.args.ssh_port,
            'telemetry_enabled': 'false'
        }

    @staticmethod
    def add_args(p):
        p.add_argument('--url', help='URL to dcos_generate_config.sh',
                       default='https://downloads.dcos.io/dcos/EarlyAccess/dcos_generate_config.sh')
        p.add_argument('--flavor', help='Machine Type (default c2m)', default='c2m')
        p.add_argument('--image', help='OS Image (default CentOS 7 (beta))', default='CentOS 7 (beta)')
        p.add_argument('--security', help='Security mode (default permissive)', default='permissive')
        p.add_argument('--ssh-user', help='SSH Username (default root)', default='root')
        p.add_argument('--ssh-port', help='SSH Port (default 22)', default=22, type=int)
        p.add_argument('--masters', help='Number of Master Instances (default 1)', default=1, type=int)
        p.add_argument('--agents', help='Number of Agent Instances (default 1)', default=1, type=int)
        p.add_argument('--pub-agents', help='Number of Public Agent Instances (default 0)', default=0, type=int)
        p.add_argument('--no-cleanup', help="Don't clean up Instances on EXIT", dest='cleanup', action='store_false',
                       default=True)
        p.add_argument('--no-error-cleanup', help="Don't clean up Instances on ERROR", dest='errclnup',
                       action='store_false', default=True)
        return p

    def deploy(self):
        self.download()
        self.swi.create_instances()
        self.write_config()
        self.system_prep()
        self.install()

    def download(self):
        dcos_url = self.args.url
        store = True
        self.log.info('Downloading DC/OS Installer from {}'.format(dcos_url))

        if dcos_url.startswith('file://'):
            local_dcos_installer = dcos_url[7:]
            if os.path.isfile(local_dcos_installer):
                if os.path.isfile(self.installer):
                    remote_installer_size = os.path.getsize(local_dcos_installer)
                    if remote_installer_size == os.path.getsize(self.installer):
                        self.log.info(
                            'Local file {} matches remote file size {} - skipping copy'.format(self.installer,
                                                                                                   remote_installer_size))
                        store = False
                if store:
                    shutil.copyfile(local_dcos_installer, self.installer)
                    self.log.info('100%')
            else:
                self.log.error("Local file {} doesn't exist".format(local_dcos_installer))
                sys.exit(1)
        else:
            r = requests.get(dcos_url, stream=True)
            remote_installer_size = int(r.headers.get('content-length'))
            if os.path.isfile(self.installer):
                local_installer_size = os.path.getsize(self.installer)
                if local_installer_size == remote_installer_size:
                    self.log.info(
                        'Local file {} matches remote file size {} - skipping download'.format(self.installer, remote_installer_size))
                    store = False
                else:
                    self.log.info(
                        "Local file {} with size {} doesn't match remote file size {}".format(self.installer, local_installer_size,
                                                                                              remote_installer_size))

            if store:
                chunk_size = 1024
                downloaded = 0
                last_per = -1
                with open(self.installer, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
                            downloaded += chunk_size
                            per = int(downloaded * 100 / remote_installer_size)
                            if per != last_per and per % 10 == 0:
                                self.log.debug('{}%'.format(per))
                            last_per = per
                    f.flush()

        os.chmod(self.installer, os.stat(self.installer).st_mode | stat.S_IEXEC)

        if not os.path.isfile('genconf/ip-detect'):
            self.log.error('genconf/ip-detect is missing'
                           ' (details: https://dcos.io/docs/1.8/administration/installing/custom/advanced/)')
            sys.exit(1)
        if not os.path.isfile('genconf/ssh_key'):
            self.log.error('genconf/ssh_key is missing (private key to ssh into nodes)')
            sys.exit(1)

    def stream_cmd(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        while p.poll() is None:
            sys.stdout.write(p.stdout.readline().decode(sys.stdout.encoding))
        if p.returncode != 0:
            msg = 'Command {} returned code {}'.format(cmd, p.returncode)
            self.log.error(msg)
            raise ValueError(msg)
        return True

    def system_prep(self):
        self.log.info('Preparing systems for DC/OS installation')
        user = self.args.ssh_user
        remote_cmd = ('sudo rpm --rebuilddb; sudo yum -y install ntp;'
                      'sudo systemctl enable ntpd; sudo systemctl start ntpd;'
                      'sudo systemctl disable firewalld; sudo systemctl stop firewalld;'
                      'echo -e "net.bridge.bridge-nf-call-iptables = 1\nnet.bridge.bridge-nf-call-ip6tables = 1"'
                      '|sudo tee /etc/sysctl.d/01-dcos-docker-overlay.conf;'
                      'sudo sysctl --system;')
        if self.args.ssh_port != 22:
            remote_cmd += ('echo -e "\nPort {}" | sudo tee -a /etc/ssh/sshd_config;'
                           'sudo systemctl restart sshd;').format(self.args.ssh_port)
        for i in self.swi.instances:
            host = i['private_ip']
            cmd = "ssh -tt -o StrictHostKeyChecking=no -o ConnectTimeout=10 -o UserKnownHostsFile=/dev/null" \
                  " -o BatchMode=yes -i genconf/ssh_key {}@{} '{}' <&-".format(user, host, remote_cmd)
            self.log.debug('Preparing {}'.format(host))
            retries = 5
            success = False
            while retries > 0 and not success:
                try:
                    self.stream_cmd(cmd)
                    success = True
                except ValueError:
                    retries -= 1
                    self.log.debug('Failed to prepare {} - {} retries left'.format(host, retries))
                    time.sleep(10)
            if not success:
                msg = 'Failed to prepare {} - aborting installation'.format(host)
                raise RuntimeError(msg)

    def bootstrap_host(self, host):
        self.log.info('Preparing bootstrap node for DC/OS Installer')
        user = self.args.ssh_user
        ssh_options = ("-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o UserKnownHostsFile=/dev/null ""
                       "-o BatchMode=yes -i genconf/ssh_key")
        remote_cmd = ('mkdir genconf;'
                      'sudo yum -y install epel-release;'
                      'sudo yum -y groupinstall "Development Tools";'
                      'sudo yum -y install yum-utils python34 python34-pip python34-devel openssl-devel;'
                      'sudo pip3 install --upgrade pip;'
                      'sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo;'
                      'sudo yum -y install docker-ce;'
                      'sudo systemctl enable docker;'
                      'sudo systemctl start docker;'
                      'sudo pip3 install scaleway-sdk retrying pyyaml;')
        cmd = "ssh -tt {} {}@{} '{}' <&-".format(ssh_options, user, host, remote_cmd)
        scp_cmd = ("scp {ssh_options} genconf/ssh_key {user}@{host}:~/genconf/ssh_key;"
                   "scp {ssh_options} genconf/ip-detect {user}@{host}:~/genconf/ip-detect;"
                   "scp {ssh_options} {script} {user}@{host}:~/dcos-install.py;"
                   ).format(ssh_options=ssh_options, user=user, host=host, script=sys.argv[0])
        self.log.debug('Preparing {}'.format(host))
        retries = 5
        success = False
        while retries > 0 and not success:
            try:
                self.stream_cmd(cmd)
                self.stream_cmd(scp_cmd)
                success = True
            except ValueError:
                retries -= 1
                self.log.debug('Failed to prepare {} - {} retries left'.format(host, retries))
                time.sleep(10)
        if not success:
            msg = 'Failed to prepare {} - aborting installation'.format(host)
            raise RuntimeError(msg)

    def install(self):
        self.log.info('Running the DC/OS installer')
        try:
            self.stream_cmd('./{} --genconf'.format(self.installer))
            self.stream_cmd('./{} --install-prereqs'.format(self.installer))
            self.stream_cmd('./{} --preflight'.format(self.installer))
            self.stream_cmd('./{} --deploy'.format(self.installer))
            self.stream_cmd('./{} --postflight'.format(self.installer))
        except ValueError:
            self.log.critical('An error occurred while installing DC/OS - aborting')
            sys.exit(1)

        if len(self.dcos_config['master_list']) > 0:
            self.log.info('DC/OS is available at the following master endpoints:')
            for master in self.dcos_config['master_list']:
                self.log.info('\thttp://{master}/\tssh://{user}@{master}'.format(master=master, user=self.args.ssh_user))

        if len(self.dcos_config['agent_list']) > 0:
            self.log.info('The following agents have been installed:')
            for agent in self.dcos_config['agent_list']:
                self.log.info('\tssh://{}@{}'.format(self.args.ssh_user, agent))

        if len(self.dcos_config['public_agent_list']) > 0:
            self.log.info('The following public agents have been installed:')
            for pubagent in self.dcos_config['public_agent_list']:
                self.log.info('\tssh://{}@{}'.format(self.args.ssh_user, pubagent))

        self.log.warning('WARNING - All host firewalls are OPEN! Service ports are publicly available!')

    def write_config(self):
        instances = self.swi.instances
        master = self.args.masters
        agents = self.args.agents
        pubagents = self.args.pub_agents
        user = self.args.ssh_user
        self.dcos_config['master_list'] = [i['private_ip'] for i in instances][:master] if master > 0 else []
        self.dcos_config['agent_list'] = [i['private_ip'] for i in instances][master:master+agents] if agents > 0 else []
        self.dcos_config['public_agent_list'] = [i['private_ip'] for i in instances][-pubagents:] if pubagents > 0 else []
        self.dcos_config['ssh_user'] = user
        with open('genconf/config.yaml', 'w') as outfile:
            outfile.write(yaml.dump(self.dcos_config))


def retry_on_apierror(exc):
    return isinstance(exc, slumber.exceptions.HttpNotFoundError)


class ScalewayInstances:
    def __init__(self, args):
        self.log = logging.getLogger(self.__class__.__name__)
        if args.errclnup:
            atexit.register(self.cleanup)
        self._args = args
        self._images = {}
        self.instances = []
        if not args.auth_token or not args.org_id:
            log.fatal('auth-token and org-id are required parameters')
            sys.exit(1)
        self._api = ComputeAPI(auth_token=self._args.auth_token, region=self._args.region)

    @staticmethod
    def add_args(p):
        p.add_argument('--org-id ', help='Scaleway Organization ID', dest='org_id', type=str,
                       default=os.environ.get('SCALEWAY_ORG_ID', None))
        p.add_argument('--auth-token', help='Scaleway Auth Token', dest='auth_token', type=str,
                       default=os.environ.get('SCALEWAY_AUTH_TOKEN', None))
        p.add_argument('--region', help='Scaleway Region (default: par1)', dest='region', type=str, default='par1')
        p.add_argument('--id', help='Cluster Identifier (default: random)', dest='cid', type=str,
                       default=str(uuid.uuid4()))
        return p

    @property
    def images(self):
        if len(self._images) == 0:
            self.log.debug('Fetching OS Images from Scaleway API')
            for image in self._api.query().images.get()['images']:
                if image['arch'] == 'x86_64':
                    self.log.debug(
                        'Found image {} with id {} ({})'.format(image['name'], image['id'], image['creation_date']))
                    self._images[image['name']] = image
        return self._images

    @retry(stop_max_attempt_number=3, wait_exponential_multiplier=1000, wait_exponential_max=30000,
           retry_on_exception=retry_on_apierror)
    def server(self, sid):
        try:
            resp = self._api.query().servers(sid).get()
            return resp['server']
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def volume(self, vid):
        try:
            resp = self._api.query().volumes(vid).get()
            return resp['volume']
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def create_server(self, name, image, commercial_type, volumes, tags=[], enable_ipv6=False):
        self.log.info("Creating server {} of type {} from image {}".format(name, commercial_type, image))
        try:
            resp = self._api.query().servers().post({'organization': self._args.org_id,
                                                     'name': name,
                                                     'image': image,
                                                     'volumes': volumes,
                                                     'commercial_type': commercial_type,
                                                     'tags': tags,
                                                     'enable_ipv6': enable_ipv6})
            return resp['server']
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def create_volume(self, name, size, volume_type='l_ssd'):
        self.log.info("Creating volume {} with size {}".format(name, size))
        try:
            resp = self._api.query().volumes().post({'name': name,
                                                     'organization': self._args.org_id,
                                                     'size': size,
                                                     'volume_type': volume_type})
            return resp['volume']
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def delete_server(self, sid):
        self.log.info("Deleting server with ID {}".format(sid))
        self.wait_for(sid, 'stopped')
        try:
            resp = self._api.query().servers(sid).delete()
            return resp
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def delete_volume(self, vid):
        self.log.info("Deleting volume with ID {}".format(vid))
        volume = self.volume(vid)
        if volume['server'] is not None:
            self.log.error("Volume with ID {} is attached to server with ID {} ({})".format(vid, volume['server']['id'],
                                                                                            volume['server']['name']))
            return False
        try:
            resp = self._api.query().volumes(vid).delete()
            return resp
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def poweron_server(self, sid):
        self.log.info("Powering ON server with ID {}".format(sid))
        return self.server_action(sid, 'poweron', target_state='running', wait_for='stopped')

    def poweroff_server(self, sid):
        self.log.info("Powering OFF server with ID {}".format(sid))
        return self.server_action(sid, 'poweroff', target_state='stopped', wait_for='running')

    def reboot_server(self, sid):
        self.log.info("Rebooting server with ID {}".format(sid))
        return self.server_action(sid, 'reboot')

    def server_action(self, sid, action, wait_for=None, target_state=None):
        if target_state:
            server = self.server(sid)
            if server['state'] == target_state:
                self.log.debug("Server {} is already in state {}".format(sid, server['state']))
                return True
        if wait_for:
            self.wait_for(sid, wait_for)
        try:
            resp = self._api.query().servers(sid).action.post({'action': action})
            return resp
        except slumber.exceptions.HttpClientError as e:
            pprint(e.content)
            raise

    def wait_for(self, sid, state):
        self.log.debug("Waiting for server {} to be in state {}".format(sid, state))
        server = self.server(sid)
        while server['state'] != state:
            self.log.debug(
                "Server {} is in state {} ({}) waiting for {}".format(sid, server['state'], server['state_detail'],
                                                                      state))
            time.sleep(10)
            server = self.server(sid)
        self.log.debug("Server {} is in state {}".format(sid, server['state']))

    def cleanup(self):
        self.log.info('Cleaning up instances')
        p = ThreadPool(10)
        p.map(self.cleanup_instance, [i['id'] for i in self.instances])

    def cleanup_instance(self, sid):
        self.log.debug('Cleaning up instance {}'.format(sid))
        server = self.server(sid)
        self.poweroff_server(sid)
        self.delete_server(sid)
        for volume in server['volumes'].values():
            self.delete_volume(volume['id'])

    def create_instances(self):
        master_id = 1
        agent_id = 1
        pub_agent_id = 1
        self.log.info('Sending master instance creation requests')
        while master_id <= self._args.masters:
            server = self.create_server('master{}'.format(master_id), self.images['CentOS 7 (beta)']['id'],
                                        self._args.flavor, {}, ['master', self._args.cid])
            self.poweron_server(server['id'])
            self.instances.append(server)
            master_id += 1
        self.log.info('Sending agent instance creation requests')
        while agent_id <= self._args.agents:
            server = self.create_server('agent{}'.format(agent_id), self.images['CentOS 7 (beta)']['id'],
                                        self._args.flavor, {}, ['agent', self._args.cid])
            self.poweron_server(server['id'])
            self.instances.append(server)
            agent_id += 1
        self.log.info('Sending public agent instance creation requests')
        while pub_agent_id <= self._args.pub_agents:
            server = self.create_server('master{}'.format(pub_agent_id), self.images['CentOS 7 (beta)']['id'],
                                        self._args.flavor, {}, ['public_agent', self._args.cid])
            self.poweron_server(server['id'])
            self.instances.append(server)
            pub_agent_id += 1

        wait = True
        while wait:
            time.sleep(10)
            wait = False
            for idx, server in enumerate(self.instances):
                updated_server = self.server(server['id'])
                self.instances[idx] = updated_server
                if updated_server['public_ip'] is None:
                    self.log.debug(
                        'Server {} ({}) is in state {} ({})'.format(updated_server['name'], updated_server['id'], updated_server['state'],
                                                               updated_server['state_detail']))
                else:
                    self.log.debug(
                        'Server {} ({}) is in state {} ({})'.format(updated_server['name'], updated_server['private_ip'],
                                                                    updated_server['state'],
                                                                    updated_server['state_detail']))
                if updated_server['state'] != 'running':
                    wait = True


if __name__ == "__main__":
    main(sys.argv[1:])
