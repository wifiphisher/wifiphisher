.. title:: Wifiphisher

.. image:: _static/wifiphisher.png


`Wifiphisher <https://www.wifiphisher.org>`_ is an effective rogue
Access Point framework used by hundreds of Wi-Fi hackers and penetration
testers everyday. It is free and open source software currently available for
Linux.

1. Download
-----------

Wifiphisher source releases are described below. The tool is distributed with
source code under the terms of the GNU General Public License.

a. Stable version
^^^^^^^^^^^^^^^^^

Wifiphisher is available for download on Github. Link is provided below.

It is recommended to verify the authenticity of a Wifiphisher release by
checking the integrity of the downloaded files. GPG detached signatures and
SHA-1 hashes for the releases are available below. You may find my public key
on the usual PGP public servers.

Latest stable Wifiphisher release gzip compressed tarball:
`wifiphisher-1.4.tar.gz (on Github) <https://github.com/wifiphisher/wifiphisher/archive/v1.4.tar.gz>`_

SHA256 Checksum: `wifiphisher-1.4.tar.gz.sha256 <http://wifiphisher.org/sigs/wifiphisher-1.4.tar.gz.sha256>`_

Signature: `wifiphisher-1.4.tar.gz.asc <http://wifiphisher.org/sigs/wifiphisher-1.4.tar.gz.asc>`_

b. Latest development
^^^^^^^^^^^^^^^^^^^^^

To clone the latest development revision using git, type the following command.

.. code:: bash

        git clone https://github.com/wifiphisher/wifiphisher.git

2. Install
-----------

a. Requirements
^^^^^^^^^^^^^^^
Following are the requirements for getting the most out of Wifiphisher:

    * Kali Linux. Although people have made Wifiphisher work on other distros, Kali Linux is the officially supported distribution, thus all new features are primarily tested on this platform.
    * One wireless network adapter that supports AP mode. Drivers should support netlink.

b. Install from Package Manager
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wifiphisher has been packaged by many Linux security distributions (including Kali Linux and Arch Linux). While these packages are generally quicker and easier to install, they are not always up-to-date. To install Wifiphisher package on Kali Linux you can type:

.. code:: bash

        apt-get install wifiphisher



c. Install from Source
^^^^^^^^^^^^^^^^^^^^^^

Assuming you downloaded and verified a Wifiphisher tar file, you can now install the tool by typing the following commands:

.. code:: bash

        tar xvf wifiphisher.tar.gz
        cd wifiphisher # Switch to tool's directory
        sudo python setup.py install # Install any dependencies


Documentation
-------------

This documentation is also available in `PDF and Epub formats
<https://readthedocs.org/projects/wifiphisher/downloads/>`_.

.. toctree::
   :titlesonly:

   extensions
   custom_phishing_scenario
   opmodes
   faq

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

This web site and all documentation is licensed under `Creative
Commons 3.0 <http://creativecommons.org/licenses/by/3.0/>`_.

