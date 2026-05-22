#!/usr/bin/env python3

import os
import sys
import shutil
import tempfile
from textwrap import dedent

# Try to use setuptools instead of distutils
try:
    from setuptools import ccompiler
    from setuptools.sysconfig import customize_compiler
except ImportError:
    try:
        from distutils import ccompiler
        from distutils.sysconfig import customize_compiler
    except ImportError:
        import sysconfig
        from distutils import ccompiler
        def customize_compiler(compiler):
            sysconfig.get_config_vars()
            compiler.set_include_dirs([sysconfig.get_path('include')])

# Code for checking if libnl-dev and libnl-genl-dev exist
LIBNL_CODE = dedent("""
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
int main(int argc, char* argv[])
{
   struct nl_msg *testmsg;
   testmsg = nlmsg_alloc();
   nlmsg_free(testmsg);
   return 0;
}
""")

# Code for checking if openssl library exist
OPENSSL_CODE = dedent("""
#include <openssl/ssl.h>
#include <openssl/err.h>
int main(int argc, char* argv[])
{
    SSL_load_error_strings();
    return 0;
}
""")

LIBNAME_CODE_DICT = {
    "netlink": LIBNL_CODE,
    "openssl": OPENSSL_CODE
}

def check_required_library(libname, libraries=None, include_dir=None):
    """
    Check if the required shared library exists

    :param libname: The name of shared library
    :type libname: str
    :return True if the required shared lib exists else false
    :rtype: bool
    """
    build_success = True
    tmp_dir = tempfile.mkdtemp(prefix='tmp_' + libname + '_')
    bin_file_name = os.path.join(tmp_dir, 'test_' + libname)
    file_name = bin_file_name + '.c'
    with open(file_name, 'w') as filep:
        filep.write(LIBNAME_CODE_DICT[libname])
    compiler = ccompiler.new_compiler()
    customize_compiler(compiler)
    try:
        compiler.link_executable(
            compiler.compile([file_name],
                             include_dirs=include_dir),
            bin_file_name,
            libraries=libraries,
        )
    except Exception:  # Changed to catch any compilation/linking error
        build_success = False
    finally:
        shutil.rmtree(tmp_dir)
    if build_success:
        return True
    err_msg = "The development package for " + \
               libname + " is required " + \
               "for the compilation of roguehostapd. " + \
               "Please install it and " + \
               "rerun the script (e.g. on Debian-based systems " \
               "run: apt-get install " 
    if libname == "openssl":
        err_msg += "libssl-dev"
    else:
        err_msg += "libnl-3-dev libnl-genl-3-dev"
    sys.exit(err_msg)

def check_dnsmasq():
    """
    Try to install dnsmasq on host machine if not present.

    :return: None
    :rtype: None
    """
    if not os.path.isfile("/usr/sbin/dnsmasq"):
        sys.exit("dnsmasq not found in /usr/sbin/dnsmasq. " + 
              "Please install dnsmasq and rerun the script " +
              "(e.g. on Debian-based systems: " +
              "apt-get install dnsmasq)")

def main():
    """Run all pre-installation checks"""
    # Check Python version
    if sys.version_info[0] < 3:
        sys.exit("Please use Python 3 to install Wifiphisher.")

    # Check for required system dependencies
    check_dnsmasq()
    
    LIB_NL3_PATH = '/usr/include/libnl3'
    LIB_SSL_PATH = '/usr/include/openssl'
    
    check_required_library("netlink", ["nl-3", "nl-genl-3"],
                           [LIB_NL3_PATH])
    check_required_library("openssl", ["ssl"],
                           [LIB_SSL_PATH])

if __name__ == "__main__":
    main() 