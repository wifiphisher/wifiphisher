Phishing Scenarios
==================
Below are the scenarios that we officially supports. There is also a community driven `repository`_ which includes more scenarios however they are not guarantee to work properly with Wifiphisher.

.. _repository: https://github.com/wifiphisher/extra-phishing-pages

Firmware Upgrade
----------------


A router configuration page asking for the password to start a firmware upgrade. After providing the password it will start a progress bar to imitate an upgrade.


.. image:: _static/firmware_upgrade_desktop.png
	:alt: Firmware Upgrade Scenario On Desktop

.. image:: _static/firmware_upgrade_mobile.png
	:alt: Firmware Upgrade Scenario On Mobile
	:scale: 40%

.. tip:: This scenario is mobile friendly.


OAUTH Login Page
----------------
A page asking for Facebook credentials in order to connect to internet for free.

.. image:: _static/oauth_desktop.png
	:alt: Firmware Upgrade Scenario On Desktop

.. image:: _static/oauth_mobile.png
	:alt: Firmware Upgrade Scenario On Mobile
	:scale: 40%

.. warning:: This scenario is **not** mobile friendly.

Browser Plugin Update
---------------------
A page asking users to update their browser plugins. This scenario allows the attacker to provide a file (malware, spyware) to serve the user.


.. image:: _static/plugin_update_mobile1.png
	:alt: Plugin Update Scenario
	:scale: 40%

.. image:: _static/plugin_update_mobile2.png
	:alt: Plugin Update Scenario
	:scale: 40%

.. tip:: This scenario is mobile friendly.


Network Manager Connect
------------------------
A page that imitates the behavior of windows or mac network manager. This template shows Chrome's "Connection Failed" page and displays a network manager window through the page asking for the password.

.. image:: _static/network_manager_desktop.png
	:alt: Network Manager Scenario On Desktop

.. image:: _static/network_manager_mobile.png
	:alt: Network Manager Scenario On Mobile
	:scale: 40%

.. tip:: This scenario is mobile friendly.
