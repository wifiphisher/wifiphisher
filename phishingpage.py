"""
This module was made to handle all the phishing related operations for
Wifiphisher.py
"""

import urllib
import os
import shutil
import copy

# set of dictionaries to store URLs and names for templates
LINKSYS = {"index.html": "http://filebin.ca/2RQWX6fTYiqP",
           "Linksys_logo.png": "http://filebin.ca/2RLKidDj7diQ",
           "bootstrap.min.js": "http://filebin.ca/2RLH8KfPvR8H",
           "bootstrap.min.css": "http://filebin.ca/2RLGpHrHURID",
           "jquery.min.js": "http://filebin.ca/2RLH1SnlHAk2",
           "upgrading.html": "http://filebin.ca/2RQXXYAi0Q4Y"}

CISCO = {"index.html": "http://filebin.ca/2RQOcIeGR6Nb",
         "cisco_logo.png": "http://filebin.ca/2RLGi6dSXPcZ",
         "bootstrap.min.js": "http://filebin.ca/2RLH8KfPvR8H",
         "bootstrap.min.css": "http://filebin.ca/2RLGpHrHURID",
         "jquery.min.js": "http://filebin.ca/2RLH1SnlHAk2",
         "upgrading.html": "http://filebin.ca/2RQTBnH8rwAo"}

TEMPLATE_DATABASE = {"Linksys": LINKSYS, "Cisco": CISCO, "minimal": None,
                     "connection_reset": None, "office365": None}

PHISHING_PAGES_DIR = "phishing-pages/"


class UrlNotAvailable(Exception):
    """ Exception class to raise in case of a invalid URL. """
    def __init__(self):
        Exception.__init__(self, "Could not reach the given URL!")


class TemplateNotAvailable(Exception):
    """ Exception class to raise in case of non-existence template. """
    def __init__(self):
        Exception.__init__(self, "The given template is not available!")


class ArgumentIsNotAString(Exception):
    """ Exception class to raise in case of non-string input. """
    def __init__(self):
        Exception.__init__(self, "The given argument is not a string!")


def fetch_template(template):
    """
    Make a new folder with the name provided in template directory and fetch
    all the files for the given template from the internet.

    Args:
        template (str): The name of requested template.

    Returns:
        None

    Raises:
        TemplateNotAvailble: If the given template is not in the
        TEMPLATE_DATABASE.
        ArgumentIsNotAString: if the given template is not a string.
    """

    # check to see if template is a string
    is_type_string(template)

    # get template_database
    template_database = get_template_database()

    # check if template exists in database
    if template in template_database:

        # make a new folder
        os.makedirs(get_path(template))

        # loop through template database
        for name in template_database[template]:

            # get the URL
            url = template_database[template][name]

            # check if URL is accessible
            if url_check(url):

                # download the files
                urllib.urlretrieve(url, (get_path(template) + "/" + name))

    else:

        # raise an error in case the template is not in the database
        raise TemplateNotAvailable()


def exists(path):
    """
    Check if the template directory in the given path exists.

    Args:
        path (str): path of a directory.

    Returns:
        True (bool): if directory exists.
        False (bool): if directory does not exist.

    Raises:
        ArgumentIsNotAString: if the given path is not a string.
        TemplateNotAvailable: if the given template is not available.
    """

    # check to see if given path is a string
    is_type_string(path)

    # get template_database
    template_database = get_template_database()

    # remove the directory and get the name of the template
    template = path[path.find("/")+1:]

    # check if template exists
    if template in template_database:

        # check the path and return accordingly
        if os.path.isdir(path):

            # in case the directory exists
            return True

        else:

            # in case the directory doesn't exist
            return False

    else:

        # raise an error in case template doesn't exists
        raise TemplateNotAvailable


def get_path(template):
    """
    Return the directory of the the given template.

    Args:
        template (str): The name of the chosen template.

    Returns:
        (str): The full path of the chosen template.

    Raises:
        ArgumentIsNotAString: if the given template name is not a string.
        TemplateNotAvailable: if the given template is not available.
    """

    # check to see if template name is a string
    is_type_string(template)

    # get phishing pages directory
    phishing_pages_dir = get_phishing_pages_dir()

    # get template_database
    template_database = get_template_database()

    # check if template exists
    if template in template_database:

        # in case the template exists
        return phishing_pages_dir + template

    else:

        # raise error in case the template doesn't exist
        raise TemplateNotAvailable


def url_check(url):
    """
    Check the accessibility of the URL.

    Args:
        url (str): The URL to be checked.

    Returns:
        True (bool): if URL exist.

    Raises:
        UrlNotAvailable: If URL is not available.
        ArgumentIsNotAString: if the given URL is not a string.
    """

    # check if url is a string
    is_type_string(url)

    # checks the URL and return value accordingly
    try:

        urllib.urlopen(url)

        # in case the URL is accessible
        return True

    except:

        # raise an error in case the URL is inaccessible
        raise UrlNotAvailable()


def check_template(template):
    """
    Check if the given template has all the files locally.

    Args:
        template (str): The template name to be checked.

    Returns:
        True (bool): If all the files are locally present.
        False (bool): If not all the files are locally present.

    Raises:
        ArgumentIsNotAString: if the given template name is not a string.
        TemplateNotAvailable: if the given template is not available.
    """

    # check if template is a string
    is_type_string(template)

    # get template_database
    template_database = get_template_database()

    # get the full path of the template
    template_path = get_path(template)

    # check to see if template exists and all the files are available
    if (exists(template_path) and
            (set(template_database[template].keys()) <=
             set(os.listdir(template_path)))):

        # in case all the files are available
        return True

    else:

        # in case all the files are not locally available
        return False


def clean_template(template):
    """
    Clean the directory and all the files for the given template.

    Agrs:
        template (str): The name of the template to be cleaned.

    Returns:
        True (bool): If the operation was successful.
        False (bool): If the operation was not successful.

    Raises:
        ArgumentIsNotAString: if the given template name is not a string.
        TemplateNotAvailable: if the given template is not available.
    """

    # check if template is a string
    is_type_string(template)

    # path to the template
    template_path = get_path(template)

    # check if the files for the template not present locally
    if not check_template(template):

        # check if the directory exists
        if exists(template_path):

            # remove the directory recursively
            shutil.rmtree(template_path)

            # in case it is removed successfully
            return True

        else:

            # in case no directory is present
            return False


def is_type_string(info):
    """
    Check if the given information is a string.

    Args:
        info (any): The information to be checked.

    Returns:
    True (bool): If the info is a string.

    Raises:
        ArgumentIsNotAString: if the given info is not a string.
    """

    if type(info) is str:
        return True
    else:
        raise ArgumentIsNotAString()


def get_template_database():
    """
    Return a copy of the TEMPLATE_DATABASE.

    Args:
        None

    Returns:
        (dict): A copy of the TEMPLATE_DATABASE.
    """

    # create a copy of the database
    template_database = copy.deepcopy(TEMPLATE_DATABASE)

    return template_database


def get_phishing_pages_dir():
    """
    Return a copy of PHISHING_PAGES_DIR.

    Args:
        None

    Returns:
        (str): A copy of the phishing_pages_dir.
    """

    # create a copy of the database
    phishing_pages_dir = copy.copy(PHISHING_PAGES_DIR)

    return phishing_pages_dir


def get_local_templates():
    """
    Return all the local templates available.

    Args:
        None

    Returns:
        (list): A list of all the local templates available.
    """

    # a list to store file names in
    local_templates = []

    # get template_database
    template_database = get_template_database()

    # get phishing pages directory
    phishing_pages_dir = get_phishing_pages_dir()

    # loop through the directory content
    for name in os.listdir(phishing_pages_dir):

        # check to see if it is a directory and not in the database
        if (os.path.isdir(os.path.join(phishing_pages_dir, name)) and
                name not in template_database):

            # add it to the list
            local_templates.append(name)

    return local_templates


def add_template(template):
    """
    Add the template to TEMPLATE_DATABASE.

    Args:
        template(str): The name of the template to be added.

    Returns:
        True (bool): If addition is successful.
        False (bool): If addition is unsuccessful.

    Raises:
        ArgumentIsNotAString: if the given info is not a string.
    """

    # check if template is a string
    is_type_string(template)

    # check to see if it is already in the database
    if template in TEMPLATE_DATABASE:

        # in case it is already in the database
        return False

    else:

        # add the template to the database
        TEMPLATE_DATABASE[template] = None

        # in case of a successful addition
        return True
