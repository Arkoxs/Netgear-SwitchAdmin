import re
import argparse
import urllib.request
import hashlib
import time

parser = argparse.ArgumentParser()
parser.add_argument('-v',       action='store_true',
                   help='Verbose')  # Not used
parser.add_argument('-a',       action='store',
                    dest='switch_ip', required=True, help='IP address of switch')
parser.add_argument('-passwd',  action='store',      dest='passwd',
                    required=True, help='Admin password of switch')
parser.add_argument('-p',       action='store',
                    dest='port',                       help='Switch Port')
parser.add_argument('-s',       action='store',      dest='port_status',
                    help='Set Switch Port Status: [on/off/status]')

global args
global results

args = parser.parse_args()

config = {
    'switch_ip': args.switch_ip,
    'passwd': args.passwd,
    'port': args.port,
    # If True, will also print out the status of the switch ports.
    'port_status': args.port_status,
    # The pseudo-random 'rand' field from the switch, used to 'encode' plaintext passwd.
    'type'
    # An input var produced from the Switch's web server, needed to identify the switch
    'rand': '',
    # An input var produced from the Switch's web server, needed to change status.
    'hash_val': '',
    # The passwd, interleaved with the supplied passwd.
    'passwd_merged': '',
    # The md5 hash of passwd_enc, what we'll actually post to the switches web interface.
    'passwd_md5': '',
    # The cookie we get back on a successful login.
    'auth_cookie': '',
    'sleep_between_calls': 1,             # Time in seconds to sleep between HTTP calls
}

#################################################################################################
# First request to get the switches 'rand' value:
#
_contents: object = urllib.request.urlopen(
    "http://%s/login.cgi" % config['switch_ip']).read().decode("utf-8").replace('\n', '')
time.sleep(config['sleep_between_calls'])

_tmp_type = re.findall(
    "^.*title>NETGEAR.(.*)</title>.*$", _contents)

_tmp_rand = re.findall(
    "^.*value=.(\d+). disabled.*$", _contents)

try:
    _type = (_tmp_type[0])
except Exception as ex:
    print("Error reading 'type' from switch:", ex)
    exit()

try:
    _rand = (_tmp_rand[0])
except Exception as ex:
    print("Error reading 'rand' from switch:", ex)
    exit()

config['type'] = _type
config['rand'] = _rand
#
# Set passwd_enc by merging plaintext password and our supplied 'rand' value:
#
i = 0
for c in config['rand']:
    if i < len(config['passwd']):
        config['passwd_merged'] += config['passwd'][i]
    i += 1
    config['passwd_merged'] += c

if i < len(config['passwd']):
    config['passwd_merged'] += config['passwd'][-(len(config['passwd'])-i):]


config['passwd_md5'] = hashlib.md5(
    config['passwd_merged'].encode()).hexdigest()

# Attempt to post to login page, so we'll get a session cookie:
data = {
    'password': config['passwd_md5'],
}

data = urllib.parse.urlencode(data).encode()
req = urllib.request.Request("http://%s/login.cgi" %config['switch_ip'], data=data)
resp = urllib.request.urlopen(req)
time.sleep(config['sleep_between_calls'])

_success_check = resp
_success_check = _success_check.read().decode("utf-8").replace('\n', '')

if 'The password is invalid' in _success_check:
    print("Netgear: ERROR: Invalid Password")
    exit()

if 'The maximum number of attempts has been reached' in _success_check:
    print("Netgear: The maximum number of attempts has been reached. Wait a few minutes and then try again")
    exit()

if 'The maximum number of sessions has been reached' in _success_check:
    print("Netgear: The maximum number of sessions has been reached. Wait a few minutes and then try again")
    exit()


# Example cookie:
# SID=cookie data string; PATH=/;HttpOnly

_cookie = re.findall("^(.*SID=.*);.*;HttpOnly$",str(resp.info()['Set-Cookie']))

try:
    _cookie = (_cookie[0])  # De-tuplify, and convert to list
    config['auth_cookie'] = _cookie

except Exception as ex:
    print("Netgear: Error reading Cookie:", ex)
    exit()

if not config['auth_cookie']:
    print("Netgear: Unable to get cookie!")
    exit()

# Read 'hash' input field from: status.cgi
# Different Netgear types need different URL's
if "GS108" in config['type']:
    req = urllib.request.Request("http://%s/status.htm" % config['switch_ip'])
elif "GS105" in config['type']:
    req = urllib.request.Request("http://%s/status.cgi" % config['switch_ip'])
else:
    print("Unknown switch, just guessing.")
    req = urllib.request.Request("http://%s/status.cgi" % config['switch_ip'])

req.add_header("Cookie", config['auth_cookie'])
_contents = urllib.request.urlopen(req)

#time.sleep(config['sleep_between_calls'])

_success_check = _contents
_success_check = _success_check.read().decode("utf-8")
_status_check_list = _success_check.splitlines()
_success_check = _success_check.replace('\n', '')

_tmp = re.findall(
    "^.*id=.hash. value=.(\d+).>.*$", _success_check)

try:
    _tmp = (_tmp[0])  # De-tuplify, and convert to list
    config['hash_val'] = _tmp

except Exception as ex:
    print("Netgear GS305E script: Error reading 'hash' from switch:", ex)
    exit()

if config['port_status'] == 'status':
    _portnumber = int(config['port'])
    _tmp_line = 58 + ((_portnumber - 1) * 19)  # Port 1 starts on line 59
    if "Disable" in _status_check_list[_tmp_line]:
        print("Netgear: Port %s is disabled" % (config['port']))
        exit(1)
    else:
        print("Netgear: Port %s is enabled" % (config['port']))
        exit(0)
else:
    _port = 'port' + config['port']
    # disable port (speed = 2) if port_status is not 'on' or 'status'
    _speed = '1' if config['port_status'] == 'on' else '2'

    data = {
        _port: 'checked',
        'SPEED': _speed,
        'FLOW_CONTROL': '2',
        'hash': config['hash_val'],
    }

    data = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request("http://%s/status.cgi" % config['switch_ip'], data=data)
    req.add_header("Cookie", config['auth_cookie'])

    resp = urllib.request.urlopen(req)
    time.sleep(config['sleep_between_calls'])