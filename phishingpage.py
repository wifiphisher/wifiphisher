"""
This module was made to handle all the phishing related operations for
Wifiphisher.py
"""

import urllib
import os
import shutil

class InvalidTemplate(Exception):
    """ Exception class to raise in case of a invalid template. """

    def __init__(self):
        Exception.__init__(self, "The given template is either invalid or " +
                                 "not available locally!")


class UrlNotAvailable(Exception):
    """ Exception class to raise in case of a invalid URL. """
    def __init__(self):
        Exception.__init__(self, "Could not reach the given URL!")


class PhishingTemplate(object):
    """ This class represents a offline phishing template. """

    def __init__(self, name, display_name="", description="", data=None):
        """
        Initialize all the necessary operations.

        Args:
            self (PhishingScenario): A PhishingTemplate object.
            name (str): The name of the template.
            description (str): The description of the template.
            data (dict) [optional]: The data used for the downloading the
            template.

        Returns:
            None
        """
        #TODO: Maybe add a category field?

        # Initialize all the variables
        self._name = name
        self._display_name = display_name
        self._description = description
        self._data = data
        self._path = "phishing-pages/" + self._name.lower()

    def get_name(self):
        """
        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (str): The name of the template as stored in the filesystem.
        """

        return self._name

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

    def is_online(self):
        """
        Return whether the template is online or not.

        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (bool): True if template is online and False otherwise.
        """

        # check the status and return accordingly
        if self._data:
            return True
        else:
            return False

    def check_data(self):
        """
        Analyze the data to check accessibility of the URL.

        Args:
            self (PhishingTemplate): An PhishingTemplate object.

        Returns:
            True (bool): If data is correct.

        Raises:
            UrlNotAvailable: If URL is not available.
        """

        # placed to avoid crash in case the URL is inaccessible
        try:
            # check every URL
            for url in self._data:
                urllib.urlopen(self._data[url])

            # in case the all the data is accessible
            return True
        except:
            raise UrlNotAvailable()

    def fetch_files(self):
        """
        Download all the required files for the template.

        Args:
            self (PhishingTemplate): An PhishingTemplate object.

        Returns:
            None
        """

        # check if URL is accessible
        if self.check_data():
            # make a new folder
            os.makedirs(self._path)

            # loop through template database
            for name in self._data:
                # get the URL and download it
                url = self._data[name]
                urllib.urlretrieve(url, (self._path + "/" + name))

    def check_file_integrity(self):
        """
        Check if an online template has its required files stored locally.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            True (bool): If all the files are locally present.
            False (bool): If not all the files are locally present.
        """

        # check if the directory exists and all files are present
        if (self.dir_exists() and
                self.is_online() and
                (set(self._data.keys())) ==
                (set(os.listdir(self._path)))):
            return True
        return False

    def dir_exists(self):
        """
        Checks if the directory exists in the filesystem.

        Agrs:
            self (TemplateManager): A TemplateManager object.

        Returns:
            True (bool): If directory exists in the filesystem
            False (bool): If directory does not exist in the filesystem
        """

        # Check if the template directory exists
        if os.path.isdir(self._path):
            return True
        return False

    def remove_local_files(self):
        """
        Remove the local copy of the template.

        Agrs:
            self (TemplateManager): A TemplateManager object.
            template (str): The name of the template to be cleaned.

        Returns:
            None
        """

        # check if the template directory exists
        if self.dir_exists():
            # remove the directory recursively
            shutil.rmtree(self._path)

    def __str__(self):
        """
        Return a string representation of the template.

        Args:
            self (PhishingTemplate): A PhishingTemplate object.

        Returns:
            (str): The name fallowed by the description of the template.
        """

        return (self._name + "\nDescription: " +
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
        self._template_directory = "phishing-pages/"

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
                       "due to a connection reset. Style changes according the user-agent " +
                       "header. Mobile-friendly.")
        connection = PhishingTemplate("connection_reset", display_name, description)

        # Office365
        display_name = "Office 365 Login Portal"
        description = ("Replica of Office 365 Login Portal. Template was taken from " +
                      "Phishing Frenzy Templates project. Mobile-friendly.")
        office = PhishingTemplate("office365", display_name, description)

        self._templates = {"connection_reset": connection, "office365": office,
                           "firmware-upgrade": firmware_upgrade}


        self.add_user_templates()

    def get_templates(self, only_online=False):
        """
        Return a dictionary containing all the templates available.

        Args:
            self (TemplateManager): A TemplateManager object.
            only_online (bool): A flag that if set returns only the online templates

        Returns:
            (dict): A dictionary containing the requested templates.
        """

        templates = self._templates.copy()
        if only_online:
            for k, v in self._templates.iteritems():
                if not v.is_online():
                    del templates[k]
        return templates

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
