Phishing Scenarios
===================

Templates
-----------

Wifiphisher supports community-built templates for different phishing scenarios.
Currently, the following phishing scenarios are in place


Firmware Upgrade Page
^^^^^^^^^^^^^^^^^^^^^^^
A router configuration page without logos or brands asking for WPA/WPA2 password due to a
firmware upgrade.

OAuth Login Page
^^^^^^^^^^^^^^^^^^^^
A free Wi-Fi Service asking for Facebook credentials to authenticate using OAuth.

.. warning::
  The template is **not** mobile friendly.


Browser Plugin Update
^^^^^^^^^^^^^^^^^^^^^^^
A generic browser plugin update page that can be used to serve payloads to the victims.

.. warning::
  The template is **not** mobile friendly.

.. note::
  The template support payloads.

Network Manager Connect
^^^^^^^^^^^^^^^^^^^^^^^^^
Imitates the behaviour of the network manager. This template shows Chrome's "Connection Failed"
page and displays a network manager window through the page asking for the pre-shared key.
Currently, the network managers of Windows and MAC OS are supported.


.. warning::
  The template is **not** mobile friendly. Also this template only imitates Windows or MAC OS.

Creating a custom phishing scenario
------------------------------------
For specific target-oriented attacks, custom scenarios may be necessary.
Creating a phishing scenario is easy and consists of two steps

Create the ``config.ini``
^^^^^^^^^^^^^^^^^^^^^^^^^^^
A config.ini file lies in template's root directory and its contents can be divided into two
sections

1. Info: This section defines the scenario's characteristics.

  * **Name** (mandatory): The name of the phishing scenario
  * **Description** (mandatory): A quick description (<50 words) of the scenario
  * **PayloadPath** (optional): If the phishing scenario pushes malwares to victims, users can
    insert the absolute path of the malicious executable here

2. Context: This section is optional and holds user-defined variables that may be later injected
to the template.

Here's an example of a config.ini file

.. code-block:: text

  # This is a comment
  [info]
  Name: ISP warning page
  Description: A warning page from victim's ISP asking for DSL credentials

  [context]
  victim_name: John Phisher
  victim_ISP: Interwebz


Create the template files
^^^^^^^^^^^^^^^^^^^^^^^^^^
A template contains the static parts of the desired HTML output and may consist of several static
``HTML`` files, images, ``CSS`` or ``Javascript`` files. Dynamic languages (e.g. ``PHP``) are
not supported.


Placeholders
^^^^^^^^^^^^^
The HTML files may also contain some special syntax (think placeholders) describing how dynamic
content will be inserted. The dynamic content may originate from two sources

Beacon frames
..................

Beacon frames contain all the information about the target network and can be used for information
gathering. The main process gathers all the interesting information and passes them to the chosen
template on the runtime.

At the time of writing, the main process passes the following data

- ``target_ap_essid`` <``str``>: The ESSID of the target Access Point
- ``target_ap_bssid`` <``str``>: The BSSID (MAC) address of the target Access Point
- ``target_ap_channel`` <``str``>: The channel of the target Access Point
- ``target_ap_vendor`` <``str``>: The vendor's name of the target Access Point
- ``target_ap_logo_path`` <``str``>: The relative path of the target Access Point vendor's logo
  in the filesystem
- ``APs_context`` <``list``>: A list containing dictionaries of the Access Points captured during
  the AP selection phase
- ``AP`` <``dict``>: A dictionary holding the following information regarding an Access Point

  - ``channel`` <``str``> The channel of the Access Point
  - ``essid`` <``str``> The ESSID of the Access Point
  - ``bssid`` <``str``> The BSSID (MAC) address of the Access Point
  - ``vendor`` <``str``> The vendor's name of the Access Point

Note that the above values may be 'None' accordingly. For example, all the target_* values will
be None if there user did not target an Access Point (by using --essid option). The
``target_ap_logo_path`` will be None if the logo of the specific vendor does not exist in
the repository.

``config.ini`` file
.....................
All the variables defined in the `Create the config.ini`_ section may be used from within the
template files. In case of naming conflicts, the variables from the configuration file will
override those coming from the beacon frames.
