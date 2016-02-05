""" This module tests all the functions in the phishingpage module. """

import unittest
import phishingpage
import os
import shutil


class TestPhishingTemplate(unittest.TestCase):
    """ Tests PhishingTemplate class. """

    def setUp(self):
        """ Sets up the variables for tests. """

        # setup name, description and data
        self._name = "test"
        self._description = "This is a description."
        self._data = {"index.html": "http://pastebin.com/raw.php?i=b0Uz1sta",
                      "Linksys_logo.png": "https://i.imgur.com/slBTPcu.png",
                      "bootstrap.min.js": "http://pastebin.com/raw/scqf9HKz",
                      "bootstrap.min.css": "http://pastebin.com/raw/LjM8RWsp",
                      "jquery.min.js": "http://pastebin.com/raw/Bms2tMTE"}

        # create the PhishingTemplate object
        self._template = phishingpage.PhishingTemplate(self._name,
                                                       self._description,
                                                       "offline")

        self._template1 = phishingpage.PhishingTemplate(self._name,
                                                        self._description,
                                                        "online", self._data)

    def tearDown(self):
        """ Tear down the tests. """

        path = self._template1.get_path()

        # if the files exists
        if os.path.isdir(path):
            # remove files
            shutil.rmtree(path)

    def test_get_name(self):
        """ Tests get_name method. """

        self.assertEqual(self._template.get_name(),
                         "test", "Failed to get the name of the template!")

    def test_str(self):
        """ Tests __str__ method. """

        expected = "test\nDescription: This is a description.\n"

        self.assertEqual(self._template.__str__(), expected,
                         "Failed to get proper __str__ string!")

    def test_is_online_online_template(self):
        """ Tests is_online method using a online template. """

        self.assertTrue(self._template1,
                        "Failed to return True for online template!")

    def test_is_online_offline_template(self):
        """ Tests is_online method using a offline template. """

        self.assertTrue(self._template,
                        "Failed to return False for offline template!")

    def test_check_data_valid(self):
        """ Tests check_data method with valid data. """

        actual = self._template1.check_data()

        self.assertEqual(actual, True,
                         "Failed to check valid data!")

    def test_check_data_invalid(self):
        """ Tests check_data method with invalid data. """

        # create an invalid data
        data = {"name1": "url1", "name2": "this is not a url"}
        template = phishingpage.PhishingTemplate("test", "None", "online",
                                                 data)

        with self.assertRaises(phishingpage.UrlNotAvailable):
            template.check_data()

    def test_fetch_files_valid(self):
        """ Tests fetch_files method with valid data """

        # fetch the files
        self._template1.fetch_files()

        # get the path of the template
        template_path = self._template1.get_path()

        # check if the directory exists and all files are present
        if (os.path.isdir(template_path) and
                (set(self._data.keys())) ==
                (set(os.listdir(template_path)))):
            pass
        else:
            self.fail("Failed to fetch all the files properly!")

    def test_fetch_files_invalid(self):
        """ Tests fetch_files method with invalid data """

        data = {"name": "url", "name2": "url2"}
        template = phishingpage.PhishingTemplate("New", "None", "online", data)

        with self.assertRaises(phishingpage.UrlNotAvailable):
            template.fetch_files()

    def test_check_file_integrity_valid(self):
        """ Tests check_file_integrity method with valid data. """

        # fetch the files
        self._template1.fetch_files()

        self.assertTrue(self._template1.check_file_integrity(),
                        "Failed to check the integrity of the files!")

    def test_check_file_integrity_invalid(self):
        """ Tests check_file_integrity method with invalid data. """

        # fetch the files
        self._template1.fetch_files()

        # get the path of the template
        template_path = self._template1.get_path()

        # remove a file
        os.remove(template_path + "/index.html")

        # add a file
        os.mknod(template_path + "/newfile.txt")

        self.assertFalse(self._template1.check_file_integrity(),
                         "Failed to return False on invalid data!")

    def test_remove_local_files(self):
        """ Tests remove_local_files method. """

        # fetch the files
        self._template1.fetch_files()

        # remove the files
        self._template1.remove_local_files()

        test = os.path.isdir(self._template1.get_path())

        self.assertFalse(test, "Failed to remove the local files!")


class TestTemplateManager(unittest.TestCase):
    """ Test TemplateManager class. """

    def setUp(self):
        """ Sets up the variables for tests. """

        self._manager = phishingpage.TemplateManager()
        self._template_path = "phishing-pages/"

    def test_get_templates(self):
        """ Tests get_templates method. """

        actual = self._manager.get_templates()

        expected = self._manager.get_templates()

        self.assertEqual(actual, expected, "Failed to get correct templates!")

    def test_find_user_templates(self):
        """ Tests find_user_templates method. """

        name = "new_template"
        path = self._template_path + name

        # create a new directory
        os.makedirs(path)

        actual = self._manager.find_user_templates()

        if name not in actual:
            self.fail("Failed to find a new template!")

        # remove the directory
        os.rmdir(path)

    def test_add_user_templates(self):
        """ Tests add_user_templates method. """

        name = "new_template"
        path = self._template_path + name

        # create a new directory
        os.makedirs(path)

        self._manager.add_user_templates()

        templates = self._manager.get_templates()

        if name not in templates:
            self.fail("Failed to add a new template!")

        # remove the directory
        os.rmdir(path)

if __name__ == '__main__':
    unittest.main()
