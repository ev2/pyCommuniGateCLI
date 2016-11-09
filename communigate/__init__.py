#!/usr/bin/python2.6
# -*- coding: utf-8 -*-

import base64
import hashlib
import re
import socket
import string
from datetime import datetime, date
from time import time


class CgDataException(Exception):
    def __init__(self, a_buffer, occurred_at, expecting=''):
        self.message = "Error parsing data returned from the server. The error occurred near '%s' (pos: %d) while " \
                       "expecting %s.\nThe data returned by the server follows:\n\n%s\n" % (
                           a_buffer[occurred_at:10], occurred_at, expecting, a_buffer)
        self.buffer = a_buffer
        self.occurred_at = occurred_at
        self.expecting = expecting

    def __str__(self):
        return self.message


class CgGeneralException(Exception):
    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return self.message


class CgDataBlock:
    def __init__(self, datastring):
        self.datablock = base64.b64encode(datastring).replace("\n", "")


def quote_string(the_string):
    return '"%s"' % the_string


class CLI(object):
    __connectionCounter = 0
    CLI_CODE_OK = 200
    CLI_CODE_OK_INLINE = 201
    CLI_CODE_PASSWORD = 300
    CLI_CODE_UNKNOWN_USER = 500
    CLI_CODE_GEN_ERR = 501
    CLI_CODE_STRANGE = 10000
    _mailboxEncoding = 'UTF7-IMAP'
    _defaultEnconding = 'UTF-8'

    def __getattribute__(self, name):
        return object.__getattribute__(self, name)

    def __methodmissing__(self, *args, **kwargs):
        cmd = [self.__missing_method_name.upper().replace('_', '')]
        for arg in args:
            cmd.append(self.print_words(arg))

        for key in kwargs.keys():
            cmd.append(key.upper())
            cmd.append(self.print_words(kwargs[key]))

        self.send(' '.join(cmd))

        if not self.is_success():
            raise CgGeneralException(self._errorMessage)

        elif self.parse_response():
            return self.parse_words(self.get_words())

    def __getattr__(self, name):
        self.__missing_method_name = name  # Could also be a property
        return getattr(self, '__methodmissing__')

    def __init__(self, peer_address, login, password, peer_port=106, timeout=60*5-5, debug=True):
        self.__missing_method_name = None  # Hack!
        self._lineSize = 1024
        self._peerAddress = string.strip(peer_address)
        self._peerPort = int(peer_port)
        self._login = string.strip(login)
        self._password = string.strip(password)
        self._timeOut = int(timeout)
        self._lastAccess = 0
        self._sp = None
        self._debug = debug
        self._logged = False  # true se já tiver autenticado na CLI
        self._bannerCode = ''  # <753.1213987978@cgate.mobimail.com.br>
        self._errorCode = 0
        self._errorMessage = ''
        self._translateStrings = 0
        self._span = 0
        self._len = 0
        self._data = ''
        self._currentCGateCommand = ''
        self._inlineResponse = ''
        self._connected = False

        arguments = ['peerAddress', 'login', 'password', 'peerPort', 'timeOut']

        for v in arguments:
            if not self.__dict__["_%s" % v]:
                raise ValueError("%s is empty" % v)

    def connect(self):
        if self._connected:
            return None

        try:
            self._sp = socket.socket()
            self._sp.connect((self._peerAddress, self._peerPort))
        except socket.error, msg:
            raise CgGeneralException(
                "Unable to connect to host %s on port %d: %s" % 
                (self._peerAddress, self._peerPort, msg))

        if self.parse_response():
            exp = re.compile(r'(<.*@.*>)')
            matches = exp.search(self._inlineResponse)
            if matches is None:
                raise ValueError("No banner from the server")
            else:
                self._bannerCode = matches.group(1)
                CLI.__connectionCounter += 1
                self._connected = True
                self._lastAccess = time()
                return
        raise CgGeneralException("Unable to connect to host %s on port %d: %s" % 
                (self._peerAddress, self._peerPort, msg))
            

    def login(self):
        m = hashlib.md5()
        m.update(self._bannerCode + self._password)
        a_hash = m.hexdigest()
        command = "APOP %s %s" % (self._login, a_hash)
        self.send(command, False)
        self.parse_response()

        if not self.is_success():
            raise CgGeneralException(self._errorMessage)

        self._logged = True
        self.inline()

    def send(self, command, check_logged=True):
        if not self._sp or ((time()-self._lastAccess) > self._timeOut):
            self._connected = False
            self._logged = False
            self._sp = None
            self.connect()
        if self._logged is not True and check_logged:
            self.login()

        self._currentCGateCommand = command
        try:
            self._sp.send("%s\r\n" % command)
        except:
            raise CgGeneralException("Cannot connect")

            
    def get_error_code(self):
        return self._errorCode

    def get_error_message(self):
        return self._errorMessage

    def get_error_command(self):
        return self._currentCGateCommand

    def is_success(self):
        return self._errorCode == CLI.CLI_CODE_OK or self._errorCode == CLI.CLI_CODE_OK_INLINE

    def set_debug(self, debug=True):
        self._debug = debug

    def set_strange_error(self, line, code):
        if isinstance(code, int):
            self._errorCode = code
        else:
            self._errorCode = CLI.CLI_CODE_STRANGE

        self._errorMessage = string.rstrip(line + "STRANGE")
        return False

    def parse_response(self):
        some_bytes = self._sp.makefile("rw", 0).readline()
        line = some_bytes.strip()

        matches = re.compile(r'^(\d+)\s(.*)$').search(line)
        if matches is not None:
            self._errorCode = int(matches.group(1))
            if self._errorCode == CLI.CLI_CODE_OK_INLINE or self._errorCode == CLI.CLI_CODE_OK:
                self._inlineResponse = matches.group(2)
                self._errorMessage = 'OK'
            else:
                self._errorMessage = string.rstrip(matches.group(2))

            return self.is_success()
        else:
            self.set_strange_error(line, CLI.CLI_CODE_STRANGE)

    def convert_output(self, data, translate):
        if data is None:
            return '#NULL#'

        elif not data:
            return ''

        elif isinstance(data, list):
            out = '('
            first = True
            for value in data:
                if not first:
                    out += ','
                else:
                    first = False
                out += self.convert_output(value, self._translateStrings)
            out += ')'
            return out

        elif isinstance(data, dict):
            out = '{'
            for k in data.keys():
                out += self.convert_output(k, self._translateStrings) + '='
                out += self.convert_output(data[k], self._translateStrings) + ';'

            out += '}'
            return out

        elif isinstance(data, int) or isinstance(data, float):
            return "#%s" % str(data)

        elif isinstance(data, datetime):
            return data.strftime("#T%d-%m-%Y_%H:%M:%S")

        elif isinstance(data, date):
            return data.strftime("#T%d-%m-%Y")

        else:
            matches = re.compile(r'[\W_]').search(data)
            if matches is not None or data == '':
                if translate:
                    data = re.compile(r'\\((?![enr\d]))').sub('\\\\' + matches.group(1), data)
                    data = data.replace('\"', '\\\"')

                for i in range(0x00, 0x1F):
                    data = data.replace(chr(i), "\\" + str(int(i)))

                data = data.replace(chr(0x7F), "\\127")
                return quote_string(data)
            else:
                return data

    def print_words(self, data):
        return self.convert_output(data, self._translateStrings)

    def get_words(self):
        if self._errorCode == CLI.CLI_CODE_OK_INLINE:
            return self._inlineResponse

        line = self._errorMessage
        line = line.strip()
        return line

    def skip_spaces(self):
        r = re.compile(r'\s')
        while (self._span < self._len) and r.search(self._data[self._span:self._span + 1]):
            self._span += 1

    def read_IP(self):
        ip = ''
        port = ''
        ip_read = False
        while self._span < self._len:
            ch = self._data[self._span]
            if not ip_read:
                if ch == ']':
                    ip_read = True
                else:
                    ip += ch
            else:
                if re.compile(r'(?::|\d)').match(ch) is None:
                    break
                elif ch != ':':
                    port += ch

            self._span += 1

        if port and len(port) > 0:
            return ip, int(port)
        else:
            return ip

    def read_time(self):
        if len(self._data) - self._span < 11 or self._data[self._span + 11] == '_':
            result = datetime.strptime(self._data[self._span:self._span + 10], '%d-%m-%Y').date()
            self._span += 10
        else:
            result = datetime.strptime(self._data[self._span:self._span + 19], '%d-%m-%Y_%H:%M:%S')
            self._span += 19

        return result

    def read_numeric(self):
        result = ''
        r = re.compile(r'[-\d.]')
        while self._span < self._len:
            ch = self._data[self._span]
            if r.match(ch) is not None:
                result += ch
                self._span += 1
            else:
                break

        if '.' in result:
            return float(result)
        else:
            return int(result)

    def read_word(self):
        is_quoted = False
        is_block = False
        result = ''
        self.skip_spaces()

        if self._data[self._span] == '"':
            is_quoted = True
            self._span += 1
        elif self._data[self._span] == '[':
            is_block = True

        while self._span < self._len:
            ch = self._data[self._span]
            if is_quoted:
                if ch == '\\':
                    if re.compile(r'^(?:\"|\\|\d\d\d)').match(self._data[self._span + 1:self._span + 4]) is not None:
                        self._span += 1
                        ch = self._data[self._span:self._span + 3]

                        if re.compile(r'\d\d\d').match(ch) is not None:
                            self._span += 2
                            ch = chr(ch)
                        else:
                            ch = ch[0]
                            if self._translateStrings:
                                ch = '\\' + ch
                elif ch == '"':
                    self._span += 1
                    break

            elif is_block:
                if ch == ']':
                    result += ch
                    self._span += 1
                    break

            elif re.compile(r'[-a-zA-Z0-9\x80-\xff_.@!#%:]').search(ch) is not None:
                pass

            else:
                break

            result += ch
            self._span += 1

        return result

    def read_key(self):
        return self.read_word()

    def read_xml_element(self):
        bra = 1
        ket = 0
        braket = 0
        stringtoparse = '<'

        while self._span < self._len:
            ch = self._data[self._span]
            if ch in '<>':
                if ch == '<':
                    bra += 1
                elif ch == '>':
                    ket += 1
                stringtoparse += ch
                if bra == ket:
                    # noinspection PyStatementEffect
                    braket
        return "#NULL#"  # TODO

    def read_value(self):
        self.skip_spaces()
        ch = self._data[self._span]
        next_ch = self._data[self._span + 1]

        if ch == '#' and next_ch == 'I':
            self._span += 3
            return self.read_IP()

        elif ch == '#' and next_ch == 'T':
            self._span += 2
            return self.read_time()

        if ch == '#' and next_ch != 'T':
            self._span += 1
            return self.read_numeric()

        elif ch == '{':
            self._span += 1
            return self.read_dictionary()

        elif ch == '(':
            self._span += 1
            return self.read_array()

        elif ch == '<':
            self._span += 1
            return self.read_xml_element()

        else:
            return self.read_word()

    def read_array(self):
        result = []
        while self._span < self._len:
            self.skip_spaces()
            if self._data[self._span] == ')':
                self._span += 1
                break
            else:
                the_value = self.read_value()
                self.skip_spaces()
                result.append(the_value)

                if self._span < self._len:
                    if self._data[self._span] == ',':
                        self._span += 1

                    elif self._data[self._span] == ')':
                        pass

                    else:
                        raise CgDataException(self._data, self._span, "','")

        return result

    def read_dictionary(self):
        result = {}
        while self._span < self._len:
            self.skip_spaces()
            if self._data[self._span:self._span + 1] == '}':
                self._span += 1
                break

            else:
                the_key = self.read_key()
                self.skip_spaces()

                if self._data[self._span:self._span + 1] != '=':
                    raise CgDataException(self._data, self._span, "=")

                self._span += 1
                result[the_key] = self.read_value()
                self.skip_spaces()

                if self._data[self._span:self._span + 1] != ';':
                    raise CgDataException(self._data, self._span, ';')

                self._span += 1

        return result

    def parse_words(self, data):
        self._data = data
        self._span = 0
        self._len = len(data)
        return self.read_value()

    def logout(self):
        self.send('QUIT')
        self.parse_response()
        self._sp.close()
        self._sp = None
        self._connected = False
        self._logged = False

if __name__ == '__main__':
    myCLI=CLI('149.132.3.52','postmaster','ahToofee6w')
    print myCLI.listlists('unimib.it')
    myCLI.logout()
    