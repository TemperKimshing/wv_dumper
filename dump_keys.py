import time
import frida
import logging

from subprocess import run

from Helpers.Scanner import Scan

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %I:%M:%S %p',
    level=logging.DEBUG,
)


def main():
    device = frida.get_usb_device()
    scanner = Scan(device.name)

    logging.info(f'Connected to {device.name}')
    logging.info('scanning all processes for the following libraries')

    for process in device.enumerate_processes():
        logging.debug(process)
        if 'drm' in process.name:
            libraries = scanner.find_widevine_process(device, process.name)
            if libraries:
                for library in libraries:
                    scanner.hook_to_process(device, process.name, library)

    logging.info('Hooks has been completed')

    if input('\nDo you want to start chrome on your device? Press "Y/y" if yes: ').lower() == 'y':
        drm_site = 'bitmovin.com/demos/drm'
        logging.info(f'Opening "{drm_site}" site on chrome browser')

        adb_path = 'adb'    # better add to your Environment Variables for global access

        try:
            run([
                adb_path, 'shell',
                'am', 'start',
                '-n', 'com.android.chrome/org.chromium.chrome.browser.ChromeTabbedActivity',
                '-d', drm_site
            ])
        except Exception:
            logging.error('adb path is not found. Make sure to add in your Environment Variables')
            logging.error('Can\'t open your browser. Just open it manually instead')
        print()

    while True:
        time.sleep(1000)


if __name__ == '__main__':
    main()
