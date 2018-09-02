"""Handles all the phishing related operations.

For specific target-oriented attacks, creating a custom Wifiphisher
phishing scenario (or phishing template) may be necessary. For example,
during a penetration testing, it may be necessary to capture the domain
credentials using a phishing page with a familiar (to the victim users)
interface, then verify the captured credentials over a local LDAP server
and finally deliver them via SMTP to a mail server that we own.
"""

from __future__ import (absolute_import, division, print_function)
import os
from shutil import copyfile
from ConfigParser import (ConfigParser, RawConfigParser)
from wifiphisher.common.utilities import config_section_map
import wifiphisher.common.constants as constants


class InvalidTemplate(Exception):
    """Exception to raise in case of an invalid template."""

    pass


class PhishingTemplate(object):
    """Represents a phishing template.

    A config.ini file lies in template’s root directory and its contents
    can be divided into two sections:

    info: This section defines the scenario’s characteristics.

        * Name (mandatory): The name of the phishing scenario.
        * Description (mandatory): A quick description (<50 words) of the scenario.
        * PayloadPath (optional): If the phishing scenario pushes
          malwares to victims, users can insert the absolute path
          of the malicious executable here.

    context: This section is optional and holds user-defined variables
    that may be later injected to the template.

    Here’s an example of a config.ini file:

    > # This is a comment
    > [info]
    > Name: ISP warning page
    > Description: A warning page from victim's ISP asking for DSL
    credentials
    >
    > [context]
    > victim_name: John Phisher
    > victim_ISP: Interwebz
    """

    def __init__(self, name):
        # type: (str) -> None
        """Intialize the class with all arguments."""
        config_path = os.path.join(constants.phishing_pages_dir, name,
                                   'config.ini')
        info = config_section_map(config_path, 'info')

        self._name = name
        self.display_name = info['name']
        self._description = info['description']
        self._payload = False
        self._config_path = os.path.join(constants.phishing_pages_dir,
                                         self._name, 'config.ini')
        if 'payloadpath' in info:
            self._payload = info['payloadpath']

        self.path = os.path.join(constants.phishing_pages_dir,
                                 self._name.lower(),
                                 constants.SCENARIO_HTML_DIR)
        self.static_path = os.path.join(constants.phishing_pages_dir,
                                        self._name.lower(),
                                        constants.SCENARIO_HTML_DIR, 'static')

        self.context = config_section_map(config_path, 'context')
        self._extra_files = []

    @staticmethod
    def update_config_file(payload_filename, config_path):
        # type: (str, str) -> None
        """Update the configuration file."""
        original_config = ConfigParser()
        original_config.read(config_path)

        # new config file object
        config = RawConfigParser()

        # update the info section
        config.add_section('info')
        options = original_config.options('info')
        for option in options:
            if option != "payloadpath":
                config.set('info', option, original_config.get('info', option))
            else:
                dirname = os.path.dirname(
                    original_config.get('info', 'payloadpath'))
                filepath = os.path.join(dirname, payload_filename)
                config.set('info', option, filepath)

        # update the context section
        config.add_section('context')
        dirname = os.path.dirname(
            original_config.get('context', 'update_path'))
        filepath = os.path.join(dirname, payload_filename)
        config.set('context', 'update_path', filepath)
        with open(config_path, 'wb') as configfile:
            config.write(configfile)

    def update_payload_path(self, filename):
        # type: (str) -> None
        """Update the path of payload."""
        config_path = self._config_path
        self.update_config_file(filename, config_path)
        # update payload attribute
        info = config_section_map(config_path, 'info')
        self._payload = False
        if 'payloadpath' in info:
            self._payload = info['payloadpath']

        self._context = config_section_map(config_path, 'context')
        self._extra_files = []

    def merge_context(self, context):
        """Merge dict context with current one.

        In case of confict always keep current values.
        """
        context.update(self._context)
        self._context = context

    def get_payload_path(self):
        """Return the payload path of the template."""
        return self._payload

    def has_payload(self):
        """Return whether the template has a payload."""
        return bool(self._payload)

    def use_file(self, path):
        # type: (str) -> Optional[str]
        """Copy a file in the filesystem to the path of the template files."""
        if path and os.path.isfile(path):
            filename = os.path.basename(path)
            copyfile(path, self.static_path + filename)
            self._extra_files.append(self.static_path + filename)
            return filename

    def remove_extra_files(self):
        # type: () -> None
        """Remove any extra files that are no longer needed."""
        for filename in self._extra_files:
            if os.path.isfile(filename):
                os.remove(filename)

    def __str__(self):
        # type: () -> str
        """Return a string representation of the template."""
        return "{display_name}\n\t{_description}\n".format(
            display_name=self.display_name, _description=self._description)


class TemplateManager(object):
    """Handles all the template management operations."""

    def __init__(self, data_pages=None):
        """Initialize the class."""
        # setup the templates
        self._template_directory = data_pages or constants.phishing_pages_dir
        if data_pages:
            constants.phishing_pages_dir = data_pages

        page_dirs = os.listdir(self._template_directory)

        self.templates = {}

        for page in page_dirs:
            if os.path.isdir(page) and self.is_valid_template(page)[0]:
                self.templates[page] = PhishingTemplate(page)

        # add all the user templates to the database
        self.add_user_templates()

    def is_valid_template(self, name):
        # type: (str) -> Tuple[bool, str]
        """Validate the template.

        Looks that a config.ini file and an html directory are placed.
        """
        html = False
        dir_path = os.path.join(self._template_directory, name)
        # check config file...
        if "config.ini" not in os.listdir(dir_path):
            return False, "Configuration file not found in: "
        try:
            tdir = os.listdir(
                os.path.join(dir_path, constants.SCENARIO_HTML_DIR))
        except OSError:
            return False, "No " + constants.SCENARIO_HTML_DIR + " directory found in: "
        # Check HTML files...
        for tfile in tdir:
            if tfile.endswith(".html"):
                html = True
                break
        if not html:
            return False, "No HTML files found in: "
        # and if we found them all return true and template directory name
        return True, name

    def find_user_templates(self):
        # type: () -> List[str]
        """Return all the available templates added by the user."""
        local_templates = []  # type: List[str]

        for name in os.listdir(self._template_directory):
            # check to see if it is a directory and not in the database
            if (os.path.isdir(os.path.join(self._template_directory, name))
                    and name not in self.templates):
                # check template
                is_valid, output = self.is_valid_template(name)
                # if template successfully validated, then...
                if is_valid:
                    local_templates.append(name)
                else:
                    # TODO: We should throw an exception instead here.
                    # but if not then display which problem occurred
                    print("[" + constants.R + "!" + constants.W + "] " +
                          output + name)

        return local_templates

    def add_user_templates(self):
        # type: () -> None
        """Add all the user templates to the database."""
        user_templates = self.find_user_templates()

        for template in user_templates:
            # create a template object and add it to the database
            local_template = PhishingTemplate(template)
            self.templates[template] = local_template

    @property
    def template_directory(self):
        return self._template_directory

    def on_exit(self):
        # type: () -> None
        """Delete any extra files on exit."""
        for templ_obj in self.templates.values():
            templ_obj.remove_extra_files()
