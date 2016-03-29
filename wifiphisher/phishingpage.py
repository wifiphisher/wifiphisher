"""
This module handles all the phishing related operations for
Wifiphisher.py
"""

import os
from constants import *


class InvalidTemplate(Exception):
    """ Exception class to raise in case of a invalid template. """

    def __init__(self):
        Exception.__init__(self, "The given template is either invalid or " +
                           "not available locally!")


class PhishingTemplate(object):
    """ This class represents a offline phishing template. """

    def __init__(self, name, display_name="", description=""):
        """
        Initialize all the necessary operations.

        Args:
            self (PhishingScenario): A PhishingTemplate object.
            name (str): The name of the template.
            description (str): The description of the template.

        Returns:
            None
        """
        # TODO: Maybe add a category field?

        # Initialize all the variables
        self._name = name
        self._display_name = display_name
        self._description = description
        self._path = PHISHING_PAGES_DIR + self._name.lower()

    def get_display_name(self):
        """
        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (str): The display name of the template.
        """

        return self._display_name

    def get_description(self):
        """
        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (str): The description of the template.
        """

        return self._description

    def get_path(self):
        """
        Return the path of the template files.

        Args:
            self (PhishingTemplate): A PhishingTemplate object.
        Returns:
            (str): The path of template files.
        """
        return self._path

    def __str__(self):
        """
        Return a string representation of the template.

        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (str): The name fallowed by the description of the template.
        """

        return (self._display_name + "\n\t" +
                self._description + "\n")


class TemplateManager(object):
    """ This class handles all the template management operations. """

    def __init__(self):
        """
        Initialize all the necessary operations.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            None
        """

        # TODO: Move templates to constants.

        # Initialize all the variables
        self._template_directory = PHISHING_PAGES_DIR

        # Firmware Upgrade
        display_name = "Firmware Upgrade Page"
        description = ("A router configuration page without logos or " +
                       "brands asking for WPA/WPA2 password due to a " +
                       "firmware upgrade. Mobile-friendly.")
        firmware_upgrade = PhishingTemplate("firmware-upgrade", display_name,
                                            description)

        # Connection Reset
        display_name = "Browser Connection Reset"
        description = ("Browser message asking for WPA/WPA2 password " +
                       "due to a connection reset. Style changes according " +
                       "the user-agent header. Mobile-friendly.")
        connection = PhishingTemplate("connection_reset", display_name,
                                      description)

        # Browser Plugin Update
        display_name = "Browser Plugin Update"
        description = ("A generic browser plugin update template that "  + 
                       "can be used to serve payloads to Windows targets. "  + 
                       "Mobile-friendly.")
        plugin_update = PhishingTemplate("plugin_update", display_name, description)


        self._templates = {"connection_reset": connection, "office365": office,
                           "firmware-upgrade": firmware_upgrade, 
                           "plugin_update": plugin_update}

        # add all the user templates to the database
        self.add_user_templates()

    def get_templates(self):
        """
        Return a dictionary containing all the templates available.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            (dict): A dictionary containing the requested templates.
        """

        return self._templates

    def find_user_templates(self):
        """
        Return all the user's templates available.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            (list): A list of all the local templates available.
        """

        # a list to store file names in
        local_templates = []

        # loop through the directory content
        for name in os.listdir(self._template_directory):
            # check to see if it is a directory and not in the database
            # TODO: Add more checks here. Does the dir contain HTML files?
            if (os.path.isdir(os.path.join(self._template_directory, name)) and
                    name not in self._templates):
                # add it to the list
                local_templates.append(name)

        return local_templates

    def add_user_templates(self):
        """
        Add all the user templates to the database.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            None
        """

        # get all the user's templates
        user_templates = self.find_user_templates()

        # loop through the templates
        for template in user_templates:
            # create a template object and add it to the database
            local_template = PhishingTemplate(template, template)
            self._templates[template] = local_template
