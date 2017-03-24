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
from pprint import pprint

log_level = logging.DEBUG
logging.basicConfig(level=logging.WARN, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger('__main__').setLevel(log_level)
logging.getLogger('ScalewayInstances').setLevel(log_level)
log = logging.getLogger(__name__)


def main(argv):
    p = argparse.ArgumentParser(description='Install DC/OS on Scaleway')
    p = ScalewayInstances.add_args(p)
    args = p.parse_args(argv)

    swi = ScalewayInstances(args)

    print("XXX CREATING SERVER")
    server = swi.create_server('master1', swi.images['CentOS 7 (beta)']['id'], 'c2s', {})
    pprint(server)
    print("XXX POWERING ON SERVER")
    pprint(swi.poweron_server(server['id']))
    print("XXX GETTING SERVER STATE")
    pprint(swi.server(server['id']))
    print("XXX POWERING OFF SERVER")
    pprint(swi.poweroff_server(server['id']))
    print("XXX DELETING SERVER")
    pprint(swi.delete_server(server['id']))
    print("XXX DELETING VOLUMES")
    for volume in server['volumes'].values():
        pprint(swi.delete_volume(volume['id']))
    #pprint(swi._api.query().servers().get())
    sys.exit(0)


class ScalewayInstances:
    def __init__(self, args):
        self.log = logging.getLogger(self.__class__.__name__)
        self._args = args
        self._images = {}
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
        p.add_argument('--id', help='Cluster Identifier (default: random)', dest='region', type=str,
                       default=str(uuid.uuid4()))
        return p

    @property
    def images(self):
        if len(self._images) == 0:
            self.log.debug('Fetching OS Images from Scaleway API')
            for image in self._api.query().images.get()['images']:
                if image['arch'] == 'x86_64':
                    self.log.debug('Found image {} with id {}'.format(image['name'], image['id']))
                    self._images[image['name']] = image
        return self._images

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
            time.sleep(5)
            server = self.server(sid)
        self.log.debug("Server {} is in state {}".format(sid, server['state']))

if __name__ == "__main__":
    main(sys.argv[1:])
