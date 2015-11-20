""" This module tests all the functions in the phishingpage module. """

import unittest
import phishingpage
import os
import shutil


class TestUrlCheck(unittest.TestCase):
    """ Tests url_check function. """

    def test_valid_url(self):
        """ Tests url_check given a valid URL and checks output. """

        url = "https://google.com"

        self.assertEqual(phishingpage.url_check(url), True,
                         "Failed to check valid URL!")

    def test_invalid_url(self):
        """ Tests url_check given an invalid URL and checks output."""

        url = "djfklsjfksjklfjsd.fsdjfsf"

        with self.assertRaises(phishingpage.UrlNotAvailable):
            phishingpage.url_check(url)


class TestGrabOnline(unittest.TestCase):
    """ Tests grab_online function. """

    def test_template_exists(self):
        """ Tests grab_online given a valid template name as an input. """

        template = "linksys"
        directory = phishingpage.PHISHING_PAGES_DIR
        path = phishingpage.get_path(template)

        phishingpage.grab_online(template)

        if template not in os.listdir(directory):
            self.fail("Failed to create the template folder!")

        shutil.rmtree(path)

    def test_template_not_exists(self):
        """ Tests grab_online with non-existence template as an input. """

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.grab_online("randomnumber")

    def test_template_empty(self):
        """ Tests grab_online with an empty string as an input. """

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.grab_online("")

    def test_template_special_character(self):
        """ Tests grab_online with special string characters as an input. """

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.grab_online("fdsjkjl#@!#")

    def test_template_int(self):
        """ Tests grab_online with an integer as an input. """

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(1)

    def test_template_float(self):
        """ Tests grab_online with a float as an input. """

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(2.4)

    def test_template_empty_list(self):
        """ Tests grab_online with an empty list as an input. """

        template = []

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_non_empty_list(self):
        """ Tests grab_online with a non-empty list as an input. """

        template = [1, 2, 3]

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_empty_dict(self):
        """ Tests grab_online with empty dictionary as an input. """

        template = dict()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_non_empty_dict(self):
        """ Tests grab_online with a non-empty dictionary as an input. """

        template = {"test": 1, "test2": 2}

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_empty_set(self):
        """ Tests grab_online with an empty set as an input. """

        template = set()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_non_empty_set(self):
        """ Test grab_online with a non-empty set as an input. """

        template = {1, 2, 3}

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(template)

    def test_template_none(self):
        """ Tests grab_online with None type as an input. """

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.grab_online(None)


class TestExists(unittest.TestCase):
    """ Tests exists function. """

    def setUp(self):
        """ Sets up the tests by creating a test directory. """

        os.makedirs("test")

    def test_directory_exists(self):
        """ Tests exists with a valid directory as an input. """

        path = "test/linksys"

        os.makedirs(path)

        self.assertEqual(phishingpage.exists(path), True,
                         "Failed to find a correct directory!")
        os.rmdir(path)

    def test_directory_not_exists(self):
        """ Tests exists with a invalid directory as an input. """

        path = "test/t2"

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.exists(path)

    def test_directory_valid_with_space(self):
        """
        Tests exists with a valid directory with spaces in it's name as
        an input.
        """

        path = "test/t 2"

        os.makedirs(path)

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.exists(path)

        os.rmdir(path)

    def tearDown(self):
        """ Removes the test directory created by the setup. """

        os.rmdir("test")


class TestGetPath(unittest.TestCase):
    """ Tests get_path function. """

    def test_valid_string_input(self):
        """ Tests get_path with a valid string as an input. """

        template_name = "minimal"
        correct = "phishing-pages/minimal"

        self.assertEqual(phishingpage.get_path(template_name), correct,
                         "Failed to return proper value!")

    def test_int_input(self):
        """ Tests get_path with an integer as an input. """

        template_name = 2

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.get_path(template_name)

    def test_float_input(self):
        """ Tests get_path with a float as an input. """

        template_name = 100.83

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.get_path(template_name)

    def test_list_input(self):
        """ Tests get_path with a list as an input. """

        template_name = []

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.get_path(template_name)

    def test_set_input(self):
        """ Tests get_path with a set as an input. """

        template_name = set()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.get_path(template_name)

    def test_dict_input(self):
        """ Tests get_path with a dictionary as an input. """

        template_name = dict()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.get_path(template_name)


class TestIsTypeString(unittest.TestCase):
    """ Tests is_type_string function. """

    def test_string_input(self):
        """ Tests is_type_string with a valid string as an input. """

        info = "test"

        self.assertEqual(phishingpage.is_type_string(info), True,
                         "Failed to return True with valid string!")

    def test_list_input(self):
        """ Tests is_type_string with a list as an input. """

        info = []

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)

    def test_set_input(self):
        """ Tests is_type_string with a set as an input. """

        info = set()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)

    def test_dict_input(self):
        """ Tests is_type_string with a dictionary as an input. """

        info = dict()

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)

    def test_int_input(self):
        """" Tests is_type_string with a integer as an input. """

        info = 25

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)

    def test_float_input(self):
        """ Tests is_type_string with a float as an input. """

        info = 1.663e4343

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)

    def test_none_input(self):
        """ Tests is_type_string with None as an input. """

        info = None

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.is_type_string(info)


class TestCheckTemplate(unittest.TestCase):
    """ Tests check_template function. """

    def test_all_files_locally_present(self):
        """ Tests check_template when all files are locally present. """

        template = "linksys"
        path = phishingpage.get_path(template)

        # download the template
        phishingpage.grab_online(template)

        self.assertEqual(phishingpage.check_template(template), True,
                         "Failed to check valid template with all files!")
        shutil.rmtree(path)

    def test_some_files_locally_present(self):
        """
        Tests check_template when some of the files are locally present.
        """

        template = "linksys"
        path = phishingpage.get_path(template)

        # download the template
        phishingpage.grab_online(template)

        # remove a file
        os.remove(path + "/index.html")

        self.assertEqual(phishingpage.check_template(template), False,
                         "Failed to check a template with some files!")
        shutil.rmtree(path)

    def test_no_files_locally_present(self):
        """
        Tests check_template when only an empty directory is locally
        present.
        """

        template = "linksys"
        path = phishingpage.get_path(template)

        # download the template
        phishingpage.grab_online(template)

        # remove all the files
        os.remove(path + "/index.html")
        os.remove(path + "/Linksys_logo.png")

        self.assertEqual(phishingpage.check_template(template), False,
                         "Failed to check a template with no files!")
        shutil.rmtree(path)

    def test_not_locally_present(self):
        """ Tests check_template when no directory is locally present. """

        template = "linksys"

        self.assertEqual(phishingpage.check_template(template), False,
                         "Failed to check a template with no directory!")

    def tests_invalid_input(self):
        """ Tests check_template when given invalid input. """

        template = 2

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.check_template(template)

    def tests_invalid_template_input(self):
        """ Tests check_template when given invalid template as an input. """

        template = "no template"

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.check_template(template)


class TestCleanTemplate(unittest.TestCase):
    """ Tests clean_template function. """

    def test_invalid_input(self):
        """ Tests clean_template when an invalid input is given. """

        template = 4.6

        with self.assertRaises(phishingpage.ArgumentIsNotAString):
            phishingpage.clean_template(template)

    def test_invalid_template_input(self):
        """ Tests clean_template when an invalid template input is given. """

        template = "no template"

        with self.assertRaises(phishingpage.TemplateNotAvailable):
            phishingpage.clean_template(template)

    def test_no_directory_available(self):
        """
        Tests clean_template when no directory is locally present for the
        template.
        """

        template = "linksys"

        self.assertEqual(phishingpage.clean_template(template), False,
                         "Failed to return False for non-existence directory!")

    def test_template_with_some_files(self):
        """
        Tests clean_template when a template with some files is given as an
        input.
        """

        template = "linksys"
        dir_path = phishingpage.PHISHING_PAGES_DIR
        path = phishingpage.get_path(template)
        local_directory_names_1 = []
        local_directory_names_2 = []

        # download the template
        phishingpage.grab_online(template)

        # remove a file
        os.remove(path + "/index.html")

        # loop through the directory content
        for name in os.listdir(dir_path):

            # check to see if it is a file
            if os.path.isdir(os.path.join(dir_path, name)):

                # add it to the list
                local_directory_names_1.append(name)

        phishingpage.clean_template(template)

        # loop through the directory content
        for name in os.listdir(dir_path):

            # check to see if it is a file
            if os.path.isdir(os.path.join(dir_path, name)):

                # add it to the list
                local_directory_names_2.append(name)

        # remove the template from original list
        local_directory_names_1.remove(template)

        self.assertListEqual(local_directory_names_1, local_directory_names_2,
                             "Failed to clean up a template!")

    def test_template_with_no_files(self):
        """ Tests clean_template when no files are locally present. """

        template = "linksys"
        dir_path = phishingpage.PHISHING_PAGES_DIR
        path = phishingpage.get_path(template)
        local_directory_names_1 = []
        local_directory_names_2 = []

        # download the template
        phishingpage.grab_online(template)

        # remove files
        os.remove(path + "/index.html")
        os.remove(path + "/Linksys_logo.png")

        # loop through the directory content
        for name in os.listdir(dir_path):

            # check to see if it is a file
            if os.path.isdir(os.path.join(dir_path, name)):

                # add it to the list
                local_directory_names_1.append(name)

        phishingpage.clean_template(template)

        # loop through the directory content
        for name in os.listdir(dir_path):

            # check to see if it is a file
            if os.path.isdir(os.path.join(dir_path, name)):

                # add it to the list
                local_directory_names_2.append(name)

        # remove the template from original list
        local_directory_names_1.remove(template)

        self.assertListEqual(local_directory_names_1, local_directory_names_2,
                             "Failed to clean up a template!")


class TestGetTemplateDatabase(unittest.TestCase):
    """ Tests get_template_database function. """

    def test_compare_unchanged(self):
        """
        Tests get_template_database contents with the original
        TEMPLATE_DATABASE.
        """
        original = phishingpage.TEMPLATE_DATABASE
        copy = phishingpage.get_template_database()

        self.assertDictEqual(original, copy,
                             "Failed to copy original TEMPLATE_DATABASE!")


def test_compare_changed(self):
    """
    Tests get_template_database contents with the original
    TEMPLATE_DATABASE when the original is changed.
    """
    original = phishingpage.TEMPLATE_DATABASE
    copy = phishingpage.get_template_database()

    # change elements in original
    del original["minimal"]

    self.assertDictEqual(original, copy,
                         "Failed to copy original TEMPLATE_DATABASE when"
                         " changed!")

if __name__ == '__main__':
    unittest.main()
