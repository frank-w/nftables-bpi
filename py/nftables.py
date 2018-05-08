import json
from ctypes import *
import sys

class Nftables:
    """A class representing libnftables interface"""

    debug_flags = {
        "scanner":   0x1,
        "parser":    0x2,
        "eval":      0x4,
        "netlink":   0x8,
        "mnl":       0x10,
        "proto-ctx": 0x20,
        "segtree":   0x40,
    }

    numeric_levels = {
        "none": 0,
        "addr": 1,
        "port": 2,
        "all":  3,
    }

    def __init__(self, sofile="libnftables.so"):
        """Instantiate a new Nftables class object.

        Accepts a shared object file to open, by default standard search path
        is searched for a file named 'libnftables.so'.

        After loading the library using ctypes module, a new nftables context
        is requested from the library and buffering of output and error streams
        is turned on.
        """
        lib = cdll.LoadLibrary(sofile)

        ### API function definitions

        self.nft_ctx_new = lib.nft_ctx_new
        self.nft_ctx_new.restype = c_void_p
        self.nft_ctx_new.argtypes = [c_int]

        self.nft_ctx_output_get_handle = lib.nft_ctx_output_get_handle
        self.nft_ctx_output_get_handle.restype = c_bool
        self.nft_ctx_output_get_handle.argtypes = [c_void_p]

        self.nft_ctx_output_set_handle = lib.nft_ctx_output_set_handle
        self.nft_ctx_output_set_handle.argtypes = [c_void_p, c_bool]

        self.nft_ctx_output_get_echo = lib.nft_ctx_output_get_echo
        self.nft_ctx_output_get_echo.restype = c_bool
        self.nft_ctx_output_get_echo.argtypes = [c_void_p]

        self.nft_ctx_output_set_echo = lib.nft_ctx_output_set_echo
        self.nft_ctx_output_set_echo.argtypes = [c_void_p, c_bool]

        self.nft_ctx_output_get_numeric = lib.nft_ctx_output_get_numeric
        self.nft_ctx_output_get_numeric.restype = c_int
        self.nft_ctx_output_get_numeric.argtypes = [c_void_p]

        self.nft_ctx_output_set_numeric = lib.nft_ctx_output_set_numeric
        self.nft_ctx_output_set_numeric.argtypes = [c_void_p, c_int]

        self.nft_ctx_output_get_stateless = lib.nft_ctx_output_get_stateless
        self.nft_ctx_output_get_stateless.restype = c_bool
        self.nft_ctx_output_get_stateless.argtypes = [c_void_p]

        self.nft_ctx_output_set_stateless = lib.nft_ctx_output_set_stateless
        self.nft_ctx_output_set_stateless.argtypes = [c_void_p, c_bool]

        self.nft_ctx_output_get_json = lib.nft_ctx_output_get_json
        self.nft_ctx_output_get_json.restype = c_bool
        self.nft_ctx_output_get_json.argtypes = [c_void_p]

        self.nft_ctx_output_set_json = lib.nft_ctx_output_set_json
        self.nft_ctx_output_set_json.argtypes = [c_void_p, c_bool]

        self.nft_ctx_output_get_debug = lib.nft_ctx_output_get_debug
        self.nft_ctx_output_get_debug.restype = c_int
        self.nft_ctx_output_get_debug.argtypes = [c_void_p]

        self.nft_ctx_output_set_debug = lib.nft_ctx_output_set_debug
        self.nft_ctx_output_set_debug.argtypes = [c_void_p, c_int]

        self.nft_ctx_buffer_output = lib.nft_ctx_buffer_output
        self.nft_ctx_buffer_output.restype = c_int
        self.nft_ctx_buffer_output.argtypes = [c_void_p]

        self.nft_ctx_get_output_buffer = lib.nft_ctx_get_output_buffer
        self.nft_ctx_get_output_buffer.restype = c_char_p
        self.nft_ctx_get_output_buffer.argtypes = [c_void_p]

        self.nft_ctx_buffer_error = lib.nft_ctx_buffer_error
        self.nft_ctx_buffer_error.restype = c_int
        self.nft_ctx_buffer_error.argtypes = [c_void_p]

        self.nft_ctx_get_error_buffer = lib.nft_ctx_get_error_buffer
        self.nft_ctx_get_error_buffer.restype = c_char_p
        self.nft_ctx_get_error_buffer.argtypes = [c_void_p]

        self.nft_run_cmd_from_buffer = lib.nft_run_cmd_from_buffer
        self.nft_run_cmd_from_buffer.restype = c_int
        self.nft_run_cmd_from_buffer.argtypes = [c_void_p, c_char_p, c_int]

        self.nft_ctx_free = lib.nft_ctx_free
        lib.nft_ctx_free.argtypes = [c_void_p]

        # initialize libnftables context
        self.__ctx = self.nft_ctx_new(0)
        self.nft_ctx_buffer_output(self.__ctx)
        self.nft_ctx_buffer_error(self.__ctx)

    def get_handle_output(self):
        """Get the current state of handle output.

        Returns a boolean indicating whether handle output is active or not.
        """
        return self.nft_ctx_output_get_handle(self.__ctx)

    def set_handle_output(self, val):
        """Enable or disable handle output.

        Accepts a boolean turning handle output on or off.

        Returns the previous value.
        """
        old = self.get_handle_output()
        self.nft_ctx_output_set_handle(self.__ctx, val)
        return old

    def get_echo_output(self):
        """Get the current state of echo output.

        Returns a boolean indicating whether echo output is active or not.
        """
        return self.nft_ctx_output_get_echo(self.__ctx)

    def set_echo_output(self, val):
        """Enable or disable echo output.

        Accepts a boolean turning echo output on or off.

        Returns the previous value.
        """
        old = self.get_echo_output()
        self.nft_ctx_output_set_echo(self.__ctx, val)
        return old

    def get_numeric_output(self):
        """Get the current state of numeric output.

        Returns a boolean indicating whether boolean output is active or not.
        """
        return self.nft_ctx_output_get_numeric(self.__ctx)

    def set_numeric_output(self, val):
        """Enable or disable numeric output.

        Accepts a boolean turning numeric output on or off.

        Returns the previous value.
        """
        old = self.get_numeric_output()

        if type(val) is str:
            val = self.numeric_levels[val]
        self.nft_ctx_output_set_numeric(self.__ctx, val)

        return old

    def get_stateless_output(self):
        """Get the current state of stateless output.

        Returns a boolean indicating whether stateless output is active or not.
        """
        return self.nft_ctx_output_get_stateless(self.__ctx)

    def set_stateless_output(self, val):
        """Enable or disable stateless output.

        Accepts a boolean turning stateless output either on or off.

        Returns the previous value.
        """
        old = self.get_stateless_output()
        self.nft_ctx_output_set_stateless(self.__ctx, val)
        return old

    def get_json_output(self):
        """Get the current state of JSON output.

        Returns a boolean indicating whether JSON output is active or not.
        """
        return self.nft_ctx_output_get_json(self.__ctx)

    def set_json_output(self, val):
        """Enable or disable JSON output.

        Accepts a boolean turning JSON output either on or off.

        Returns the previous value.
        """
        old = self.get_json_output()
        self.nft_ctx_output_set_json(self.__ctx, val)
        return old

    def get_debug(self):
        """Get currently active debug flags.

        Returns a set of flag names. See set_debug() for details.
        """
        val = self.nft_ctx_output_get_debug(self.__ctx)

        names = []
        for n,v in self.debug_flags.items():
            if val & v:
                names.append(n)
                val &= ~v
        if val:
            names.append(val)

        return names

    def set_debug(self, values):
        """Set debug output flags.

        Accepts either a single flag or a set of flags. Each flag might be
        given either as string or integer value as shown in the following
        table:

        Name      | Value (hex)
        -----------------------
        scanner   | 0x1
        parser    | 0x2
        eval      | 0x4
        netlink   | 0x8
        mnl       | 0x10
        proto-ctx | 0x20
        segtree   | 0x40

        Returns a set of previously active debug flags, as returned by
        get_debug() method.
        """
        old = self.get_debug()

        if type(values) in [str, int]:
            values = [values]

        val = 0
        for v in values:
            if type(v) is str:
                v = self.debug_flags[v]
            val |= v

        self.nft_ctx_output_set_debug(self.__ctx, val)

        return old

    def cmd(self, cmdline):
        """Run a simple nftables command via libnftables.

        Accepts a string containing an nftables command just like what one
        would enter into an interactive nftables (nft -i) session.

        Returns a tuple (rc, output, error):
        rc     -- return code as returned by nft_run_cmd_from_buffer() fuction
        output -- a string containing output written to stdout
        error  -- a string containing output written to stderr
        """
        rc = self.nft_run_cmd_from_buffer(self.__ctx, cmdline, len(cmdline))
        output = self.nft_ctx_get_output_buffer(self.__ctx)
        error = self.nft_ctx_get_error_buffer(self.__ctx)

        return (rc, output, error)

    def json_cmd(self, json_root):
        """Run an nftables command in JSON syntax via libnftables.

        Accepts a hash object as input.

        Returns a tuple (rc, output, error):
        rc     -- reutrn code as returned by nft_run_cmd_from_buffer() function
        output -- a hash object containing library standard output
        error  -- a string containing output written to stderr
        """
        json_out_old = self.set_json_output(True)
        rc, output, error = self.cmd(json.dumps(json_root))
        if not json_out_old:
            self.set_json_output(json_out_old)
        if len(output):
            output = json.loads(output)
        return (rc, output, error)
