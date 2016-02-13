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

    def __init__(self, name, display_name, description, data=None):
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
        Check if the template has all the files locally.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            True (bool): If all the files are locally present.
            False (bool): If not all the files are locally present.
        """

        # check if the directory exists and all files are present
        if (os.path.isdir(self._path) and
                (set(self._data.keys())) ==
                (set(os.listdir(self._path)))):
            return True
        else:
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
        if os.path.isdir(self._path):
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

        # Initialize all the variables
        self._template_directory = "phishing-pages/"

        # Linksys
        data = {"index.html": "http://pastebin.com/raw.php?i=b0Uz1sta",
                "Linksys_logo.png": "https://i.imgur.com/slBTPcu.png",
                "bootstrap.min.js": "http://pastebin.com/raw/scqf9HKz",
                "bootstrap.min.css": "http://pastebin.com/raw/LjM8RWsp",
                "jquery.min.js": "http://pastebin.com/raw/Bms2tMTE"}
        display_name = "Linksys"
        description = "test"
        linksys = PhishingTemplate("linksys", display_name, description, data)

        # Minimal
        display_name = "Minimal"
        description = "test"
        minimal = PhishingTemplate("minimal", display_name, description)

        # Connection Reset
        display_name = "Connection Reset"
        description = "test"
        connection = PhishingTemplate("connection_reset", display_name, description)

        # Office365
        display_name = "Office"
        description = "test"
        office = PhishingTemplate("office365", display_name, description)

        self._templates = {"Linksys": linksys, "minimal": minimal,
                           "connection_reset": connection, "office365": office}

    def get_templates(self):
        """
        Return a dictionary containing all the templates available.

        Args:
            self (TemplateManager): A TemplateManager object.

        Returns:
            (dict): A dictionary containing all the templates.
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
            temp = PhishingTemplate(template, "Not Available", "Not Available", "offline")
            self._templates[template] = temp
