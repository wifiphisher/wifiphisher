"""
This module was made to handle the curses sections for the ap selection,
template selection and the main window
"""

import os
import time
import re
from collections import namedtuple
from subprocess import check_output
import curses
import wifiphisher.common.constants as constants
import wifiphisher.common.recon as recon
import wifiphisher.common.phishingpage as phishingpage

# information for the main terminal
MainInfo = namedtuple("MainInfo", constants.MAIN_TUI_ATTRS)
# information for the AP selection terminal
ApSelInfo = namedtuple("ApSelInfo", constants.AP_SEL_ATTRS)


class TuiTemplateSelection(object):
    """
    TUI to do Template selection
    """

    def __init__(self):
        """
        Construct the class
        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        :return None
        :rtype None
        """

        self.green_text = None
        # heightlight the phishing scenario
        self.heightlight_text = None
        # record current hightlight template number
        self.heightlight_number = 0
        # store the current page number
        self.page_number = 0
        # store the phishing contents of each scenario
        self.sections = list()
        # map the section to page number
        self.sec_page_map = {}
        # the window size for (y, x)
        self.dimension = [0, 0]

    def get_sections(self, template_names, templates):
        """
        Get all the phishing scenario contents and store them
        in a list
        :param self: A TuiTemplateSelection object
        :param template_names: A list of string
        :param templates: A dictionary
        :type self: TuiTemplateSelection
        :type template_names: list
        :type templates: dict
        :return None
        :rtype: None
        """

        for name in template_names:
            phishing_contents = " - " + str(templates[name])
            # total line in the phishing contents
            lines = phishing_contents.splitlines()
            # split the line into 15 words per shorter line
            short_lines = []
            for line in lines:
                for short_line in line_splitter(15, line):
                    short_lines.append(short_line)
            self.sections.append(short_lines)

    def update_sec_page_map(self, last_row):
        """
        Update the page number for each section
        :param self: A TuiTemplateSelection object
        :param last_row: The last row of the window
        :type self: TuiTemplateSelection
        :type last_row: int
        :return: None
        :rtype: None
        """

        page_number = 0
        row_number = 0
        self.sec_page_map = {}
        for number, section in enumerate(self.sections):
            row_number += len(section)
            if row_number > last_row:
                row_number = 0
                page_number += 1
            self.sec_page_map[number] = page_number

    def gather_info(self, template_argument, template_manager):
        """
        Select a template based on whether the template argument
        is set or not. If the template argument is not set, it will
        interfactively ask user for a template
        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        :param template_argument: The template argument which might
        have been entered by the user
        :type template_argument: str
        :param template_manager: A TemplateManager object
        :type template_manager: TemplateManager
        :return A PhishingTemplate object
        :rtype: PhishingTemplagte
        :raises  InvalidTemplate in case the template argument entered
        by the user is not available.
        """
        # get all available templates
        templates = template_manager.templates

        # get all the templates names for display
        template_names = list(templates.keys())

        # get all the section contents
        self.get_sections(template_names, templates)

        # check if the template argument is set and is correct
        if template_argument and template_argument in templates:
            # return the template name
            return templates[template_argument]
        elif template_argument and template_argument not in templates:
            # in case of an invalid template
            raise phishingpage.InvalidTemplate(
                "{template_argument} is either invalid or"
                "not available locally!".format(
                    template_argument=template_argument))
        else:
            # prompt interactive phishing scenarios to let user select one
            template = curses.wrapper(self.display_info, templates,
                                      template_names)
        return template

    def key_movement(self, screen, number_of_sections, key):
        """
        Check for key movement and hightlight the corresponding
        phishing scenario

        :param self: A TuiTemplateSelection object
        :param number_of_sections: Number of templates
        :param key: The char user keying
        :type self: TuiTemplateSelection
        :type number_of_sections: int
        :type key: str
        :return: None
        :rtype: None
        """

        if key == curses.KEY_DOWN:
            if self.heightlight_number < number_of_sections - 1:
                page_number = self.sec_page_map[self.heightlight_number + 1]
                if page_number > self.page_number:
                    self.page_number += 1
                    screen.erase()
                self.heightlight_number += 1
        elif key == curses.KEY_UP:
            if self.heightlight_number > 0:
                page_number = self.sec_page_map[self.heightlight_number - 1]
                if page_number < self.page_number:
                    self.page_number -= 1
                    screen.erase()
                self.heightlight_number -= 1

    def display_phishing_scenarios(self, screen):
        """
        Display the phishing scenarios
        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :return total row numbers used to display the phishing scenarios
        :rtype: int
        """

        try:
            max_window_height, max_window_len = screen.getmaxyx()
            if self.dimension[0] != max_window_height or\
                    self.dimension[1] != max_window_len:
                screen.erase()
            self.dimension[0] = max_window_height
            self.dimension[1] = max_window_len
            # add margins for changing the pages
            self.update_sec_page_map(max_window_height - 20)
            display_str = "Options: [Up Arrow] Move Up  [Down Arrow] Move Down"
            screen.addstr(0, 0, display_string(max_window_len, display_str))
            display_str = "Available Phishing Scenarios:"
            screen.addstr(3, 0, display_string(max_window_len, display_str),
                          curses.A_BOLD)
        except curses.error:
            return 0

        # add blank line
        row_num = 5
        first = False
        for number, short_lines in enumerate(self.sections):
            try:

                # incase user shrink the window and the heightlight section
                # is in the next page. for this case, just shift the
                # heightlight section to the first scenario in the first
                # page
                if self.sec_page_map[self.heightlight_number] !=\
                        self.page_number and not first:
                    # heightlight the first scenario
                    screen.addstr(row_num, 2, short_lines[0],
                                  self.heightlight_text)
                    self.heightlight_number = 0
                    self.page_number = 0
                    first = True

                # display the sections belonged to the current page
                if self.sec_page_map[number] != self.page_number:
                    continue

                screen.addstr(row_num, 0, str(number + 1), self.green_text)

                # emphasize the phishing scenario
                if number == self.heightlight_number:
                    screen.addstr(row_num, 2, short_lines[0],
                                  self.heightlight_text)
                else:
                    screen.addstr(row_num, 2, short_lines[0], curses.A_BOLD)
                row_num += 1
                # add 8 spaces to the first line
                screen.addstr(row_num, 8, short_lines[1])
                row_num += 1
                if len(short_lines) > 1:
                    for short_line in short_lines[2:]:
                        screen.addstr(row_num, 0, short_line)
                        row_num += 1
                # add blank line between phishing scenarios
                row_num += 1
            except curses.error:
                return row_num

        return row_num

    def display_info(self, screen, templates, template_names):
        """
        Display the template information to users
        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param templates: A dictionay map page to PhishingTemplate
        :type templates: dict
        :param template_names: list of template names
        :type template_names: list
        """

        # setup curses
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.nodelay(True)
        curses.init_pair(1, curses.COLOR_GREEN, screen.getbkgd())
        # heightlight the phishing scenarios
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)

        self.green_text = curses.color_pair(1) | curses.A_BOLD
        self.heightlight_text = curses.color_pair(2) | curses.A_BOLD

        # setup number of templates
        number_of_sections = len(templates)

        # how many chars for user keying the template number
        screen.erase()
        while True:
            # display the four default phishing scenarios
            # catch the exception when screen size is smaller than
            # the text length
            row_number = self.display_phishing_scenarios(screen)

            # update the heightlight_number
            key = screen.getch()
            self.key_movement(screen, number_of_sections, key)
            # add two blank lines
            row_number += 2
            # display the words of chosen template
            if key == ord("\n"):
                try:
                    screen.addstr(
                        row_number, 3, "YOU HAVE SELECTED " +
                        template_names[self.heightlight_number], curses.A_BOLD)
                except curses.error:
                    pass
                screen.refresh()
                time.sleep(1)
                template_name = template_names[self.heightlight_number]
                template = templates[template_name]
                return template
            screen.refresh()


class ApDisplayInfo(object):
    """
    ApDisplayInfo class to store the information for ap selection
    """

    def __init__(self, pos, page_number, box, box_info):
        """
        Construct the class
        :param self: ApDisplayInfo
        :param pos: position of the line in the ap selection page
        :param page_number: page number of the ap selection
        :param box: the curses.newwin.box object containing ap information
        :param key: the key user have keyed in
        :param box_info: list of window height, window len, and max row number
        :type self: ApDisplayInfo
        :type pos: int
        :type page_number: int
        :type box: curse.newwin.box
        :type key: str
        :return: None
        :rtype: None
        """

        self.pos = pos
        self.page_number = page_number
        self.box = box
        # list of (max_win_height, max_win_len, max_row, key)
        self._box_info = box_info

    @property
    def max_h(self):
        """
        The height of the terminal screen
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: the height of terminal screen
        :rtype: int
        """

        return self._box_info[0]

    @max_h.setter
    def max_h(self, val):
        """
        Set the height of the terminal screen
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: None
        :rtype: None
        """

        self._box_info[0] = val

    @property
    def max_l(self):
        """
        The width of the terminal screen
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: the width of terminal screen
        :rtype: int
        """

        return self._box_info[1]

    @max_l.setter
    def max_l(self, val):
        """
        Set the width of the terminal screen
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: None
        :rtype: None
        """

        self._box_info[1] = val

    @property
    def max_row(self):
        """
        Maximum row numbers used to contain the ap information
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: The row numbers of the box that contains the ap info
        :rtype: int
        """

        return self._box_info[2]

    @max_row.setter
    def max_row(self, val):
        """
        Set maximum row numbers used to contain the ap information
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: None
        :rtype: None
        """

        self._box_info[2] = val

    @property
    def key(self):
        """
        Get the key the users have keyed
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: The key
        :rtype: int
        """

        return self._box_info[3]

    @key.setter
    def key(self, val):
        """
        Set the key the users have keyed
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :return: None
        :rtype: None
        """

        self._box_info[3] = val


class TuiApSel(object):
    """
    TuiApSel class to represent the ap selection terminal window
    """

    def __init__(self):
        """
        Construct the class
        :param self: A TuiApSel object
        :type self: TuiApSel
        :return: None
        :rtype: None
        """

        self.total_ap_number = 0
        self.access_points = list()
        self.access_point_finder = None
        self.highlight_text = None
        self.normal_text = None
        self.mac_matcher = None
        # when screen becomes too small we'll create a box with
        # the size equal to the screen terminal. We need to renew
        # the box when the screen terminal expands again.
        self.renew_box = False

    def init_display_info(self, screen, info):
        """
        Initialization of the ApDisplyInfo object
        :param self: A TuiApSel object
        :type self: TuiApSel
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param info: A namedtuple of information from pywifiphisher
        :type info: namedtuple
        :return ApDisplayInfo object
        :rtype: ApDisplayInfo
        """
        position = 1
        page_number = 1

        # get window height, length and create a box inside
        max_window_height, max_window_length = screen.getmaxyx()
        if max_window_height < 14 or max_window_length < 9:
            box = curses.newwin(max_window_height, max_window_length, 0, 0)
            self.renew_box = True
        else:
            box = curses.newwin(max_window_height - 9, max_window_length - 5,
                                4, 3)
        box.box()

        # calculate the box's maximum number of row's
        box_height = box.getmaxyx()[0]
        # subtracting 2 from the height for the border
        max_row = box_height - 2
        key = 0
        box_info = [max_window_height, max_window_length, max_row, key]

        ap_info = ApDisplayInfo(position, page_number, box, box_info)

        self.mac_matcher = info.mac_matcher
        # start finding access points
        self.access_point_finder = recon.AccessPointFinder(
            info.interface, info.network_manager)
        if info.args.lure10_capture:
            self.access_point_finder.capture_aps()
        self.access_point_finder.find_all_access_points()

        return ap_info

    def gather_info(self, screen, info):
        """
        Get the information from pywifiphisher and print them out
        :param self: A TuiApSel object
        :type self: TuiApSel
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param info: A namedtuple of information from pywifiphisher
        :type info: namedtuple
        :return AccessPoint object if users type enter
        :rtype AccessPoint if users type enter else None
        """
        # setup curses
        # make cursor invisible
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        # don't wait for user input
        screen.nodelay(True)
        # setup the font color
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        self.highlight_text = curses.color_pair(1)
        self.normal_text = curses.A_NORMAL

        # information regarding access points
        ap_info = self.init_display_info(screen, info)

        # show information until user presses Esc key
        while ap_info.key != 27:
            # display info will modifiy the key value
            is_done = self.display_info(screen, ap_info)

            if is_done:
                # turn off access point discovery and return the result
                self.access_point_finder.stop_finding_access_points()
                return self.access_points[ap_info.pos - 1]

        # turn off access point discovery
        self.access_point_finder.stop_finding_access_points()

    def resize_window(self, screen, ap_info):
        """
        Resize the window if the dimensions have been changed

        :param self: A TuiApSel object
        :type self: TuiApSel
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param ap_info: An ApDisplayInfo object
        :type ap_info: ApDisplayInfo
        """

        if screen.getmaxyx() != (ap_info.max_h, ap_info.max_l):
            ap_info.max_h, ap_info.max_l = screen.getmaxyx()
            # sanity check for the box size (the height needed is 10 and
            # the width needed is 6. Just create a box which is same as the
            # base screen
            if ap_info.max_h < 10 + 4 or ap_info.max_l < 6 + 3:
                box = curses.newwin(ap_info.max_h, ap_info.max_l, 0, 0)
                box.box()
                ap_info.box = box
                self.renew_box = True
                return
            elif self.renew_box:
                screen.erase()
                box = curses.newwin(ap_info.max_h - 9, ap_info.max_l - 5, 4, 3)
                box.box()
                ap_info.box = box
                self.renew_box = False

            ap_info.box.resize(ap_info.max_h - 9, ap_info.max_l - 5)
            # calculate the box's maximum number of row's
            box_height = ap_info.box.getmaxyx()[0]
            # subtracting 2 from the height for the border
            ap_info.max_row = box_height - 2
            # reset the page and position to avoid problems
            ap_info.pos = 1
            ap_info.page_number = 1

    def key_movement(self, ap_info):
        """
        Check for any key movement and update it's result

        :param self: A TuiApSel object
        :type self: TuiApSel
        :param ap_info: ApDisplayInfo object
        :type: ApDisplayInfo
        :return: None
        :rtype: None
        """

        key = ap_info.key
        pos = ap_info.pos
        max_row = ap_info.max_row
        page_number = ap_info.page_number

        # in case arrow down key has been pressed
        if key == curses.KEY_DOWN:
            # if next item exists move down, otherwise don't move
            try:
                self.access_points[pos]
            except IndexError:
                ap_info.key = 0
                ap_info.pos = pos
                ap_info.max_row = max_row
                return

            # if next item is in the next page change page and move
            # down otherwise just move down)
            if pos % max_row == 0:
                pos += 1
                page_number += 1
            else:
                pos += 1

        # in case arrow up key has been pressed
        elif key == curses.KEY_UP:
            # if not the first item
            if (pos - 1) > 0:
                # if previous item is in previous page_number, change page
                # and move up otherwise just move up
                if (pos - 1) % max_row == 0:
                    pos -= 1
                    page_number -= 1
                else:
                    pos -= 1
        # update key, position, and page_number
        ap_info.key = key
        ap_info.pos = pos
        ap_info.page_number = page_number

    def display_info(self, screen, ap_info):
        """
        Display the AP informations on the screen

        :param self: A TuiApSel object
        :type self: TuiApSel
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param ap_info: An ApDisplayInfo object
        :type ap_info: ApDisplayInfo
        :return True if ap selection is done
        :rtype: bool
        """

        is_apsel_end = False
        self.resize_window(screen, ap_info)

        # check if any new access points have been discovered
        new_total_ap_number = len(
            self.access_point_finder.observed_access_points)

        if new_total_ap_number != self.total_ap_number:
            self.access_points = self.access_point_finder.\
                get_sorted_access_points()
            self.total_ap_number = len(self.access_points)

        # display the information to the user
        self.display_access_points(screen, ap_info)
        # check for key movement and store result
        self.key_movement(ap_info)

        # ask for a key input (doesn't block)
        ap_info.key = screen.getch()
        if ap_info.key == ord("\n") and self.total_ap_number != 0:
            # show message and exit
            screen.addstr(
                ap_info.max_h - 2, 3, "YOU HAVE SELECTED " +
                self.access_points[ap_info.pos - 1].name)
            screen.refresh()
            time.sleep(1)
            is_apsel_end = True
        return is_apsel_end

    def display_access_points(self, screen, ap_info):
        """
        Display information in the box window

        :param self: A TuiApSel object
        :type self: TuiApSel
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param ap_info: An ApDisplayInfo object
        :type ap_info: ApDisplayInfo
        :return: None
        :rtype: None
        .. note: The display system is setup like the following:

                 ----------------------------------------
                 - (1,3)Options                         -
                 -   (3,5)Header                        -
                 - (4,3)****************************    -
                 -      *       ^                  *    -
                 -      *       |                  *    -
                 -      *       |                  *    -
                 -    < *       |----              *    -
                 -    v *       |   v              *    -
                 -    v *       |   v              *    -
                 -    v *       |   v              *    -
                 -    v *       v   v              *    -
                 -    v ************v***************    -
                 -    v             v      v            -
                 -----v-------------v------v-------------
                      v             v      v
                      v             v      > max_window_length-5
                      v             v
                max_window_height-9 v
                                    V
                                    v--> box_height-2

        """

        # get the page boundary
        page_boundary = range(
            1 + (ap_info.max_row * (ap_info.page_number - 1)), ap_info.max_row
            + 1 + (ap_info.max_row * (ap_info.page_number - 1)))

        # remove previous content and draw border
        ap_info.box.erase()
        ap_info.box.border(0)

        # show the header
        header_fmt = "{0:30} {1:16} {2:3} {3:4} {4:9} {5:5} {6:20}"
        header = header_fmt.format("ESSID", "BSSID", "CH", "PWR", "ENCR",
                                   "CLIENTS", "VENDOR")
        opt_str = ("Options:  [Esc] Quit  [Up Arrow] Move Up  "
                   "[Down Arrow] Move Down")

        try:
            window_l = screen.getmaxyx()[1]
            screen.addstr(1, 3, display_string(window_l - 3, opt_str))
            screen.addstr(3, 5, display_string(window_l - 5, header))
        except curses.error:
            return

        # show all the items based on their position
        for item_position in page_boundary:
            # in case of no access points discovered yet
            if self.total_ap_number == 0:
                display_str = "No access point has been discovered yet!"
                try:
                    ap_info.box.addstr(
                        1, 1, display_string(ap_info.max_l - 1, display_str),
                        self.highlight_text)
                except curses.error:
                    return
            # in case of at least one access point
            else:
                # get the access point and it's vendor
                access_point = self.access_points[item_position - 1]
                vendor = self.mac_matcher.get_vendor_name(
                    access_point.mac_address)

                # the display format for showing access points
                display_text = ((
                    "{0:30} {1:17} {2:2} {3:3}% {4:^8} {5:^5}"
                    " {6:20}").format(
                        access_point.name, access_point.mac_address,
                        access_point.channel, access_point.signal_strength,
                        access_point.encryption,
                        access_point.client_count, vendor))
                # shows whether the access point should be highlighted or not
                # based on our current position
                print_row_number = item_position - ap_info.max_row * (
                    ap_info.page_number - 1)

                # bypass the addstr exception
                try:

                    if item_position == ap_info.pos:
                        ap_info.box.addstr(
                            print_row_number, 2,
                            display_string(ap_info.max_l - 2, display_text),
                            self.highlight_text)
                    else:
                        ap_info.box.addstr(
                            print_row_number, 2,
                            display_string(ap_info.max_l - 2, display_text),
                            self.normal_text)
                except curses.error:
                    return

                # stop if it is the last item in page
                if item_position == self.total_ap_number:
                    break

        # update the screen
        screen.refresh()
        ap_info.box.refresh()


class TuiMain(object):
    """
    TuiMain class to represent the main terminal window
    """

    def __init__(self):
        """
        Construct the class
        :param self: A TuiMain object
        :type self: TuiMain
        :return: None
        :rtype: None
        """

        self.blue_text = None
        self.orange_text = None
        self.yellow_text = None

    def gather_info(self, screen, info):
        """
        Get the information from pywifiphisher and print them out
        :param self: A TuiMain object
        :param screen: A curses window object
        :param info: A namedtuple of printing information
        :type self: TuiMain
        :type screen: _curses.curses.window
        :type info: namedtuple
        :return: None
        :rtype: None
        """

        # setup curses
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        screen.nodelay(True)
        curses.init_pair(1, curses.COLOR_BLUE, screen.getbkgd())
        curses.init_pair(2, curses.COLOR_YELLOW, screen.getbkgd())
        self.blue_text = curses.color_pair(1) | curses.A_BOLD
        self.yellow_text = curses.color_pair(2) | curses.A_BOLD

        while True:
            # catch the exception when screen size is smaller than
            # the text length
            is_done = self.display_info(screen, info)
            if is_done:
                return

    def print_http_requests(self, screen, start_row_num, http_output):
        """
        Print the http request on the main terminal
        :param self: A TuiMain object
        :type self: TuiMain
        :param start_row_num: start line to print the http request
        type start_row_num: int
        :param http_output: string of the http requests
        :type http_output: str
        """

        requests = http_output.splitlines()
        match_str = r"(.*\s)(request from\s)(.*)(\sfor|with\s)(.*)"
        for request in requests:
            # match the information from the input string
            match = re.match(match_str, request)
            if match is None:
                continue

            # POST or GET
            request_type = match.group(1)
            # requst from
            request_from = match.group(2)
            # ip address or http address
            ip_address = match.group(3)
            # for or with
            for_or_with = match.group(4)
            resource = match.group(5)

            start_col = 0
            screen.addstr(start_row_num, start_col, '[')
            start_col += 1
            screen.addstr(start_row_num, start_col, '*', self.yellow_text)
            start_col += 1
            screen.addstr(start_row_num, start_col, '] ')
            start_col += 2

            # concatenate GET or POST
            screen.addstr(start_row_num, start_col, request_type,
                          self.yellow_text)
            start_col += len(request_type)

            # concatenate the word 'request from'
            screen.addstr(start_row_num, start_col, request_from)
            start_col += len(request_from)

            # concatenate the ip address
            screen.addstr(start_row_num, start_col, ip_address,
                          self.yellow_text)
            start_col += len(ip_address)

            # concatenate with or for
            screen.addstr(start_row_num, start_col, for_or_with)
            start_col += len(for_or_with)

            # resource url
            screen.addstr(start_row_num, start_col, resource, self.yellow_text)

            start_row_num += 1

    def display_info(self, screen, info):
        """
        Print the information of Victims on the terminal
        :param self: A TuiMain object
        :param screen: A curses window object
        :param info: A nameduple of printing information
        :type self: TuiMain
        :type screen: _curses.curses.window
        :type info: namedtuple
        :return True if users have pressed the Esc key
        :rtype: bool
        """

        is_done = False
        screen.erase()

        _, max_window_length = screen.getmaxyx()
        try:
            # print the basic info on the right top corner
            screen.addstr(0, max_window_length - 30, "|")
            screen.addstr(1, max_window_length - 30, "|")
            # continue from the "Wifiphisher"
            screen.addstr(1, max_window_length - 29,
                          " Wifiphisher " + info.version, self.blue_text)

            screen.addstr(2, max_window_length - 30,
                          "|" + " ESSID: " + info.essid)
            screen.addstr(3, max_window_length - 30,
                          "|" + " Channel: " + info.channel)
            screen.addstr(4, max_window_length - 30,
                          "|" + " AP interface: " + info.ap_iface)
            screen.addstr(5, max_window_length - 30,
                          "|" + " Options: [Esc] Quit")
            screen.addstr(6, max_window_length - 30, "|" + "_" * 29)

            # Print the extensions section
            screen.addstr(1, 0, "Extensions feed: ", self.blue_text)
        except curses.error:
            pass

        if info.em:
            # start raw number from 2
            raw_num = 2
            for client in info.em.get_output()[-5:]:
                screen.addstr(raw_num, 0, client)
                raw_num += 1
        try:
            # print the dhcp lease section
            screen.addstr(7, 0, "DHCP Leases: ", self.blue_text)
            if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
                dnsmasq_output = check_output(
                    ['head', '-5', '/var/lib/misc/dnsmasq.leases'])
                screen.addstr(8, 0, dnsmasq_output)

            # print the http request section
            screen.addstr(13, 0, "HTTP requests: ", self.blue_text)
            if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
                http_output = check_output(
                    ['tail', '-5', '/tmp/wifiphisher-webserver.tmp'])
                self.print_http_requests(screen, 14, http_output)
        except curses.error:
            pass

        # detect if users have pressed the Esc Key
        if screen.getch() == 27:
            is_done = True

        if info.phishinghttp.terminate and info.args.quitonsuccess:
            is_done = True

        screen.refresh()
        return is_done


def display_string(w_len, target_line):
    """
    Display the line base on the max length of window length
    :param w_len: length of window
    :param target_line: the target display string
    :type w_len: int
    :type target_line: str
    :return: The final displaying string
    :rtype: str
    """

    return target_line if w_len >= len(target_line) else target_line[:w_len]


def line_splitter(num_of_words, line):
    """
    Split line to the shorter lines
    :param num_of_words: split the line into the line with lenth equeal
    to num_of_words
    :type num_of_words: int
    :param line: A sentence
    :type line: str
    :return: tuple of shorter lines
    :rtype: tuple
    """
    pieces = line.split()
    return (" ".join(pieces[i:i + num_of_words])
            for i in xrange(0, len(pieces), num_of_words))
