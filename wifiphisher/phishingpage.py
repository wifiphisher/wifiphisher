#pylint: skip-file
"""
This module handles all the phishing related operations for
Wifiphisher.py
"""

import os
from constants import *
from shutil import copyfile

import ConfigParser


def config_section_map(config_file, section):
    """
    Map the values of a config file to a dictionary.
    """

    config = ConfigParser.ConfigParser()
    config.read(config_file)
    dict1 = {}

    if section not in config.sections():
        return dict1

    options = config.options(section)
    for option in options:
        try:
            dict1[option] = config.get(section, option)
        except:
            dict1[option] = None
    return dict1


class InvalidTemplate(Exception):
    """ Exception class to raise in case of a invalid template """

    def __init__(self):
        Exception.__init__(self, "The given template is either invalid or " +
                           "not available locally!")


class PhishingTemplate(object):
    """ This class represents phishing templates """

    def __init__(self, name):
        """
        Construct object.

        :param self: A PhishingTemplate object
        :type self: PhishingScenario
        :return: None
        :rtype: None
        .. todo:: Maybe add a category field
        """

        # setup all the variables

        config_path = os.path.join(PHISHING_PAGES_DIR, name, 'config.ini')
        info = config_section_map(config_path, 'info')

        self._name = name
        self._display_name = info['name']
        self._description = info['description']
        self._payload = False
        if 'payloadpath' in info:
            self._payload = info['payloadpath']

        self._path = PHISHING_PAGES_DIR + self._name.lower() + "/"
        self._path_static = PHISHING_PAGES_DIR + self._name.lower() + "/static/"

        self._context = config_section_map(config_path, 'context')
        self._extra_files = []

    def merge_context(self, context):
        """
            Merge dict context with current one
            In case of confict always keep current values
        """
        context.update(self._context)
        self._context = context

    def get_context(self):
        """
        Return the context of the template.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the context of the template
        :rtype: dict
        """

        return self._context

    def get_display_name(self):
        """
        Return the display name of the template.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the display name of the template
        :rtype: str
        """

        return self._display_name

    def get_payload_path(self):
        """
        Return the payload path of the template.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: The path of the template
        :rtype: bool
        """

        return self._payload

    def has_payload(self):
        """
        Return whether the template has a payload.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: boolean if it needs payload
        :rtype: bool
        """

        if self._payload:
            return True
        return False

    def get_description(self):
        """
        Return the description of the template.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the description of the template
        :rtype: str
        """

        return self._description

    def get_path(self):
        """
        Return the path of the template files.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the path of template files
        :rtype: str
        """

        return self._path

    def get_path_static(self):
        """
        Return the path of the static template files.
        JS, CSS, Image files lie there.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the path of static template files
        :rtype: str
        """

        return self._path_static

    def use_file(self, path):
        """
        Copies a file in the filesystem to the path
        of the template files.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :param path: path of the file that is to be copied
        :type self: str
        :return: the path of the file under the template files
        :rtype: str
        """

        if path is not None and os.path.isfile(path):
            filename = os.path.basename(path)
            copyfile(path, self.get_path_static() + filename)
            self._extra_files.append(self.get_path_static() + filename)
            return filename

    def remove_extra_files(self):
        """
        Removes extra used files (if any)

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: None
        :rtype: None
        """

        for f in self._extra_files:
            if os.path.isfile(f):
                os.remove(f)

    def __str__(self):
        """
        Return a string representation of the template.

        :param self: A PhishingTemplate object
        :type self: PhishingTemplate
        :return: the name followed by the description of the template
        :rtype: str
        """

        return (self._display_name + "\n\t" + self._description + "\n")


class TemplateManager(object):
    """ This class handles all the template management operations """

    def __init__(self):
        """
        Construct object.

        :param self: A TemplateManager object
        :type self: TemplateManager
        :return: None
        :rtype: None
        """

        # setup the templates
        self._template_directory = PHISHING_PAGES_DIR

        page_dirs = os.listdir(PHISHING_PAGES_DIR)

        self._templates = {}

        for page in page_dirs:
            if os.path.isdir(page):
                self._templates[page] = PhishingTemplate(page)

        # add all the user templates to the database
        self.add_user_templates()

    def get_templates(self):
        """
        Return all the available templates.

        :param self: A TemplateManager object
        :type self: TemplateManager
        :return: all the available templates
        :rtype: dict
        """

        return self._templates

    def find_user_templates(self):
        """
        Return all the user's templates available.

        :param self: A TemplateManager object
        :type self: TemplateManager
        :return: all the local templates available
        :rtype: list
        .. todo:: check to make sure directory contains HTML files
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

        :param self: A TemplateManager object
        :type: self: TemplateManager
        :return: None
        :rtype: None
        """

        # get all the user's templates
        user_templates = self.find_user_templates()

        # loop through the templates
        for template in user_templates:
            # create a template object and add it to the database
            local_template = PhishingTemplate(template)
            self._templates[template] = local_template
