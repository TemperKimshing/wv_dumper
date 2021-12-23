import os
import json
import logging

from pathlib import Path
from Crypto.PublicKey import RSA
from google.protobuf import message
from .Keybox import Keybox
from .wv_proto2_pb2 import SignedLicenseRequest


class Scan:
    def __init__(self, device_name):
        self.logger = logging.getLogger(__name__)
        self.KEY_DUMP_LOC = 'keydump/'
        self.device_name = device_name
        self.saved_keys = {}

        self.key_dumps = Path('key_dumps')
        self.license_request_fname = 'license_request.bin'
        self.client_id_blob_fname = 'device_client_id_blob.bin'
        self.private_key_fname = 'device_private_key.pem'

        self.frida_script = open('Helpers/script.js', 'r').read()
        self.device = {
            'device_id': None,
            'device_token': None,
            'device_key': os.urandom(16).hex(),
            'security_level': ''
        }
        self.widevine_libraries = [
            'libwvhidl.so',
            'libwvdrmengine.so',
            'liboemcrypto.so',
            'libmediadrm.so',
            'libwvdrm_L1.so',
            'libWVStreamControlAPI_L1.so',
            'libdrmwvmplugin.so',
            'libwvm.so'
        ]

    def export_key(self, k):
        root = SignedLicenseRequest()
        root.ParseFromString(k['id'])
        cid = root.Msg.ClientId
        system_id = cid.Token._DeviceCertificate.SystemId

        save_dir = self.key_dumps.joinpath(
            f'{self.device_name.replace(" ", "-")}-{system_id}',
            f'{str(k["key"].n)[:10]}'
        )
        save_dir.mkdir(exist_ok=True, parents=True)

        client_id_blob_file = save_dir / self.client_id_blob_fname
        with client_id_blob_file.open('wb+') as wb:
            wb.write(cid.SerializeToString())

        private_key_file = save_dir / self.private_key_fname
        with private_key_file.open('wb+') as wb:
            wb.write(k['key'].exportKey('PEM'))

        self.logger.info(f'Key pairs saved to: {save_dir}')

    def on_message(self, msg, data):
        try:
            if msg['payload'] == 'priv':
                self.logger.debug('processing private key')
                self.private_key_message(msg, data)
            elif msg['payload'] == 'id':
                self.logger.debug('processing id')
                self.license_request_message(data)
            elif msg['payload'] == 'device_id':
                self.logger.debug('processing device id')
                self.device_id_message(data)
            elif msg['payload'] == 'device_token':
                self.logger.debug('processing device token')
                self.device_token_message(data)
            elif msg['payload'] == 'security_level':
                lvl = '1' if data.decode() == 'L1' else '3'
                self.device['security_level'] = f'LVL{lvl}'
            elif msg['payload'] == 'aes_key':
                self.aes_key_message(data)
            elif msg['payload'] == 'message':
                payload = json.loads(data.decode())
                self.logger.debug(json.dumps(payload, indent=4))
            elif msg['payload'] == 'message_info':
                self.logger.info(data.decode())
        except Exception:
            self.logger.error('unable to process the message')
            self.logger.error(msg)
            self.logger.error(data)

    def private_key_message(self, private_key_message, data):
        try:
            try:
                key = RSA.importKey(data)
                cur = self.saved_keys.get(key.n, {})
                if 'id' in cur:
                    if 'key' not in cur:
                        cur['key'] = key
                        self.saved_keys[key.n] = cur
                        self.export_key(cur)
                else:
                    self.saved_keys[key.n] = {'key': key}
            except Exception:
                self.logger.error('unable to load private key')
                self.logger.error(data)
                pass
        except Exception:
            self.logger.error('payload of type priv failed')
            self.logger.error(private_key_message)

    def license_request_message(self, data):
        with Path(self.license_request_fname).open('wb+') as f:
            f.write(data)

        root = SignedLicenseRequest()

        try:
            root.ParseFromString(data)
        except message.DecodeError:
            return

        try:
            key = RSA.importKey(root.Msg.ClientId.Token._DeviceCertificate.PublicKey)
            cur = self.saved_keys.get(key.n, {})
            if 'key' in cur:
                if 'id' not in cur:
                    cur['id'] = data
                    self.saved_keys[key.n] = cur
                    self.export_key(cur)
            else:
                self.saved_keys[key.n] = {'id': data}
        except Exception as error:
            self.logger.error(error)

    def device_id_message(self, data_buffer):
        if not self.device['device_id']:
            self.device['device_id'] = data_buffer.hex()
        if (self.device['device_id']
                and self.device['device_token']
                and self.device['device_key']):
            self.save_key_box()

    def device_token_message(self, data_buffer):
        if not self.device['device_token']:
            self.device['device_token'] = data_buffer.hex()
        if self.device['device_id'] and self.device['device_token']:
            self.save_key_box()

    def aes_key_message(self, data_buffer):
        if not self.device['device_key']:
            self.device['device_key'] = data_buffer.hex()
        if self.device['device_id'] and self.device['device_token']:
            self.save_key_box()

    def find_widevine_process(self, dev, process_name):
        process = dev.attach(process_name)
        script = process.create_script(self.frida_script)
        script.load()
        loaded = []

        try:
            for lib in self.widevine_libraries:
                try:
                    loaded.append(script.exports.widevinelibrary(lib))
                except Exception:
                    pass
        finally:
            process.detach()
            return loaded

    def hook_to_process(self, device, process, library):
        session = device.attach(process)
        script = session.create_script(self.frida_script)
        script.on('message', self.on_message)
        script.load()
        script.exports.inject(library, process)
        return session

    def save_key_box(self):
        try:
            if (self.device['device_id'] is not None
                    and self.device['device_token'] is not None):

                self.logger.info('saving key box')

                keybox = Keybox(self.device)

                box = self.key_dumps / f'{self.device_name}/key_boxes/{keybox.system_id}'
                box.mkdir(exist_ok=True, parents=True)

                keybox_bin = box / f'{keybox.system_id}.bin'
                keybox_json = box / f'{keybox.system_id}.json'

                self.logger.info(f'saving keybox bin to {keybox_bin}')

                keybox_bin.write_bytes(keybox.get_keybox())
                keybox_json.write_text(keybox.__repr__())

                self.logger.info(f'keybox has been saved to: {box}')
        except Exception as error:
            self.logger.error('unable to save keybox')
            self.logger.error(error)
