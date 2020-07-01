#!/usr/bin/env python3
# coding: UTF-8

"""Encapsulates a session with an nsrlsvr instance.  Using it is pretty
straightforward: create the object (specifying host and port if necessary),
then use .add_file() to add filenames.  It will compute MD5 hashes of the
files and keep track of all files fed to it.  Once you're done, call
.run_query() to contact the remote nsrlsvr and ask it to look up values.

When .run_query() finishes it will return a dictionary with keys of "known"
and "unknown".  The values associated with these keys are themselves dicts,
mapping an MD5 hash value to the set of input files that hashed out to
that.

If you're going to re-use an NSRLLookup object, remember to call .clear()
between uses!"""


from hashlib import md5
from typing import Dict, Set
from socket import socket, AF_INET, AF_INET6, SOCK_STREAM, SHUT_RDWR
from re import compile as regex
from sys import stderr
from os import walk, sep


class NetworkError(Exception):
    """Represents a network failure between this system and a remote nsrlsvr
    instance.  This is normally only thrown if the network is down or the
    remote system is refusing connections."""
    def __init__(self):
        super(NetworkError, self).__init__("nsrlsvr instance unreachable")


class NsrlsvrError(Exception):
    """Represents an error in the interaction with nsrlsvr.  This should never
    be thrown: if it gets thrown, please file a bug."""
    def __init__(self, cause: str = "Unspecified"):
        super(NsrlsvrError, self).__init__(cause)


class NSRLLookup:
    """Encapsulates a session with an nsrlsvr instance.  Using it is pretty
    straightforward: create the object (specifying host and port if necessary),
    then use .add_file() to add filenames.  It will compute MD5 hashes of the
    files and keep track of all files fed to it.  Once you're done, call
    .run_query() to contact the remote nsrlsvr and ask it to look up values.

    When .run_query() finishes it will return a dictionary with keys of "known"
    and "unknown".  The values associated with these keys are themselves dicts,
    mapping an MD5 hash value to the set of input files that hashed out to
    that.

    If you're going to re-use an NSRLLookup object, remember to call .clear()
    between uses!"""

    def __init__(self, server: str = "nsrllookup.com", port: int = 9120):
        self.cache: Dict[str, Set[str]] = {}
        self.server: str = server
        self.port: int = port
        self.force_ipv4: bool = False
        self.regex = regex(r"^(OK|NOT OK)(\s+[01]*)?$")

        try:
            with socket(AF_INET6, SOCK_STREAM) as sock:
                sock.connect((self.server, self.port))
                sock.send("BYE\r\n".encode("UTF-8"))
                sock.shutdown(SHUT_RDWR)
        except Exception:
            self.force_ipv4 = True
            try:
                with socket(AF_INET, SOCK_STREAM) as sock:
                    sock.connect((self.server, self.port))
                    sock.send("BYE\r\n".encode("UTF-8"))
                    sock.shutdown(SHUT_RDWR)
            except Exception:
                raise NetworkError()

    def clear(self) -> None:
        """Clears the internal cache of filenames and MD5 hashes."""
        self.cache = {}

    def add_file(self, filename: str) -> None:
        """Calculates the MD5 hash of a given file, then stores the fulename
        and hash in the internal cache."""
        engine = md5()
        with open(filename, "rb") as filehandle:
            data = filehandle.read(1 << 20)
            while len(data) > 0:
                engine.update(data)
                data = filehandle.read(1 << 20)
        hash_value: str = engine.hexdigest().upper()
        if hash_value not in self.cache:
            self.cache[hash_value] = set()
        if filename not in self.cache[hash_value]:
            self.cache[hash_value].add(filename)

    def add_directory(self, dirname: str) -> None:
        """Like add_file, but recursively reads everything in a directory."""
        for path, _, files in walk(dirname):
            for name in [sep.join([path, X]) for X in files]:
                self.add_file(name)

    def run_query(self) -> Dict[str, Dict[str, Set[str]]]:
        """Sends cached MD5 hashes to the server, then compiles a report on
        which values were found in the server's hash database and which
        weren't."""
        return_value: Dict[str, Dict[str, Set[str]]] = {
            "known": {},
            "unknown": {}
        }

        if len(self.cache.keys()) == 0:
            return return_value

        hashes = sorted(list(self.cache.keys()))
        try:
            with socket(AF_INET if self.force_ipv4 else AF_INET6,
                        SOCK_STREAM) as sock:
                sock.connect((self.server, self.port))
                sock.send("Version: 2.0\r\n".encode("UTF-8"))
                resp: str = sock.recv(1024).decode("UTF-8").strip()
                if resp != "OK":
                    raise NsrlsvrError("bad handshake")

                start: int = 0
                while start < len(hashes):
                    block: str = ' '.join(hashes[start:start + 4096])
                    querystr: str = "QUERY " + block + "\r\n"
                    sock.send(querystr.encode("UTF-8"))
                    resp = sock.recv(16384).decode("UTF-8").strip()
                    match = self.regex.match(resp)
                    if not match:
                        raise NsrlsvrError("unknown response: " + resp)
                    if match.group(1) == "NOT OK":
                        raise NsrlsvrError("submitted garbage data")
                    matches = match.group(2).strip()

                    for (index, value) in enumerate(matches):
                        hash_value: str = hashes[start + index]
                        if value == '0':
                            return_value["unknown"][hash_value] = \
                                self.cache[hash_value]
                        else:
                            return_value["known"][hash_value] = \
                                self.cache[hash_value]
                    start += 4096
                sock.send("BYE\r\n".encode("UTF-8"))
                sock.shutdown(SHUT_RDWR)
            return return_value
        except NsrlsvrError as server_error:
            print("nsrlsvr error: {}".format(str(server_error)), file=stderr)
            raise server_error
        except Exception as general_error:
            print("nsrlsvr error: {}".format(str(general_error)), file=stderr)
            raise general_error


if __name__ == '__main__':
    NSRL = NSRLLookup()
    NSRL.add_directory("/bin")
    RESULT = NSRL.run_query()

    for kind in ["known", "unknown"]:
        print("{} files:".format(kind))
        for key in RESULT[kind]:
            FILES = ", ".join(RESULT[kind][key])
            print("\t{}: {}".format(key, FILES))
