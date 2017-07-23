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
        # record the key which users keying
        self.key = None
        # heightlight the phishing scenario
        self.heightlight_text = None
        # record current hightlight template number
        self.heightlight_number = 0
        # total number of templates
        self.number_of_templates = 0

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
        templates = template_manager.get_templates()

        # get all the templates names for display
        template_names = list(templates.keys())

        # check if the template argument is set and is correct
        if template_argument and template_argument in templates:
            # return the template name
            return templates[template_argument]
        elif template_argument and template_argument not in templates:
            # in case of an invalid template
            raise phishingpage.InvalidTemplate
        else:
            # prompt interactive phishing scenarios to let user select one
            template = curses.wrapper(self.display_info, templates,
                                      template_names)
        return template

    def key_movement(self):
        """
        Check for key movement and hightlight the corresponding
        phishing scenario

        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        """
        if self.key == curses.KEY_DOWN:
            if self.heightlight_number < self.number_of_templates - 1:
                self.heightlight_number += 1
        elif self.key == curses.KEY_UP:
            if self.heightlight_number > 0:
                self.heightlight_number -= 1

    def display_phishing_scenarios(self, screen, templates, template_names):
        """
        Display the phishing scenarios
        :param self: A TuiTemplateSelection object
        :type self: TuiTemplateSelection
        :param screen: A curses window object
        :type screen: _curses.curses.window
        :param templates: A dictionay map page to PhishingTemplate
        :type templates: dict
        :param template_names: list of template names
        :type template_names: list
        :return total row numbers used to display the phishing scenarios
        :rtype: int
        """
        screen.addstr(0, 0,
                      ("Options: [Up Arrow] Move Up  "
                       "[Down Arrow] Move Down"))

        screen.addstr(3, 0, "Available Phishing Scenarios:",
                      curses.A_BOLD)
        # add blank line
        row_num = 5
        for number, name in enumerate(template_names):
            screen.addstr(row_num, 0, str(number + 1), self.green_text)
            phishing_contents = " - " + str(templates[name])
            # total line in the phishing contents
            lines = phishing_contents.splitlines()
            # split the line into 15 words per shorter line
            short_lines = []
            for line in lines:
                for short_line in line_splitter(15, line):
                    short_lines.append(short_line)

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
        curses.curs_set(0)
        screen.nodelay(True)
        curses.init_pair(1, curses.COLOR_GREEN, screen.getbkgd())
        # heightlight the phishing scenarios
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)

        self.green_text = curses.color_pair(1) | curses.A_BOLD
        self.heightlight_text = curses.color_pair(2) | curses.A_BOLD

        # setup number of templates
        self.number_of_templates = len(templates)

        # how many chars for user keying the template number
        screen.erase()
        while True:
            # display the four default phishing scenarios
            # catch the exception when screen size is smaller than
            # the text length
            try:
                row_number = self.display_phishing_scenarios(
                    screen, templates, template_names)

                # update the heightlight_number
                self.key_movement()
                self.key = screen.getch()

                # add two blank lines
                row_number += 2
                # display the words of chosen template
                if self.key == ord("\n"):
                    screen.addstr(row_number, 3, "YOU HAVE SELECTED " +
                                  template_names[self.heightlight_number],
                                  curses.A_BOLD)
                    screen.refresh()
                    time.sleep(1)
                    template_name = template_names[self.heightlight_number]
                    template = templates[template_name]
                    return template
                screen.refresh()
            except curses.error:
                pass


class ApDisplayInfo(object):
    """
    ApDisplayInfo class to store the information for ap selection
    """

    def __init__(self, pos, page_number, max_h, max_l, box, max_row,
                 key, mac_matcher):
        """
        Construct the class
        :param self: ApDisplayInfo
        :type self: ApDisplayInfo
        :param pos: position of the line in the ap selection page
        :type pos: int
        :param page_number: page number of the ap selection
        :type page_number: int
        :param max_h: maximum window height of the ap selection terminal
        :type max_h: int
        :param max_l: maximum window length of the ap selection terminal
        :type max_l: int
        :param box: the curses.newwin.box object containing ap information
        :type box: curse.newwin.box
        :param max_row: the maximum row numbers of the page
        :type max_row: int
        :param key: the key user have keyed in
        :type key: str
        :param mac_matcher: mac_matcher object
        :type mac_matcher: MACMatcher
        :return: None
        :rtype: None
        """

        self.pos = pos
        self.page_number = page_number
        self.max_h = max_h
        self.max_l = max_l
        self.box = box
        self.max_row = max_row
        self.mac_matcher = mac_matcher
        self.key = key


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

        self.exit_key = 27
        self.total_ap_number = 0
        self.access_points = list()
        self.access_point_finder = None
        self.highlight_text = None
        self.normal_text = None

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
        box = curses.newwin(max_window_height-9, max_window_length-5, 4, 3)
        box.box()

        # calculate the box's maximum number of row's
        box_height = box.getmaxyx()[0]
        # subtracting 2 from the height for the border
        max_row = box_height-2
        key = 0
        ap_info = ApDisplayInfo(position, page_number, max_window_height,
                                max_window_length, box, max_row, key,
                                info.mac_matcher)

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
        curses.curs_set(0)
        # don't wait for user input
        screen.nodelay(True)
        # setup the font color
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
        self.highlight_text = curses.color_pair(1)
        self.normal_text = curses.A_NORMAL

        # information regarding access points
        ap_info = self.init_display_info(screen, info)

        # show information until user presses Esc key
        while ap_info.key != self.exit_key:
            # display info will modifiy the key value
            try:
                is_done = self.display_info(screen, ap_info)
            except curses.error:
                pass
            if is_done:
                # turn off access point discovery and return the result
                self.access_point_finder.stop_finding_access_points()
                return self.access_points[ap_info.pos-1]

        # turn off access point discovery
        self.access_point_finder.stop_finding_access_points()

    @staticmethod
    def resize_window(screen, ap_info):
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
            ap_info.box.resize(ap_info.max_h-9, ap_info.max_l-5)
            # calculate the box's maximum number of row's
            box_height = ap_info.box.getmaxyx()[0]
            # subtracting 2 from the height for the border
            ap_info.max_row = box_height-2
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
            if (pos-1) > 0:
                # if previous item is in previous page_number, change page
                # and move up otherwise just move up
                if (pos-1) % max_row == 0:
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
        new_total_ap_number = self.access_point_finder.\
            get_all_access_points()

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
            screen.addstr(ap_info.max_h-2, 3, "YOU HAVE SELECTED " +
                          self.access_points[ap_info.pos-1].get_name())
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
        page_boundary = range(1+(ap_info.max_row*(ap_info.page_number-1)),
                              ap_info.max_row+1+(
                                  ap_info.max_row*(ap_info.page_number-1)))

        # remove previous content and draw border
        ap_info.box.erase()
        ap_info.box.border(0)

        # show the header
        header = ("{0:30} {1:16} {2:3} {3:4} {4:5} {5:5} {6:20}".format(
            "ESSID", "BSSID", "CH", "PWR", "ENCR", "CLIENTS", "VENDOR"))
        screen.addstr(1, 3,
                      ("Options:  [Esc] Quit  [Up Arrow] Move Up  "
                       "[Down Arrow] Move Down"))
        screen.addstr(3, 5, header)

        # show all the items based on their position
        for item_position in page_boundary:
            # in case of no access points discovered yet
            if self.total_ap_number == 0:
                ap_info.box.addstr(1, 1,
                                   "No access point has been discovered yet!",
                                   self.highlight_text)

            # in case of at least one access point
            else:
                # get the access point and it's vendor
                access_point = self.access_points[item_position-1]
                vendor = ap_info.mac_matcher.get_vendor_name(
                    access_point.get_mac_address())

                # the display format for showing access points
                display_text = ("{0:30} {1:17} {2:2} {3:3}% {4:^7} {5:^5} {6:20}"
                                .format(access_point.get_name(),
                                        access_point.get_mac_address(),
                                        access_point.get_channel(),
                                        access_point.get_signal_strength(),
                                        access_point.get_encryption(),
                                        access_point.
                                        get_number_connected_clients(),
                                        vendor))

                # shows whether the access point should be highlighted or not
                # based on our current position
                print_row_number = item_position - ap_info.max_row * (
                    ap_info.page_number - 1)

                if item_position == ap_info.pos:
                    ap_info.box.addstr(print_row_number, 2,
                                       display_text, self.highlight_text)
                else:
                    ap_info.box.addstr(
                        print_row_number,
                        2, display_text, self.normal_text)

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
        curses.curs_set(0)
        screen.nodelay(True)
        curses.init_pair(1, curses.COLOR_BLUE, screen.getbkgd())
        curses.init_pair(2, curses.COLOR_YELLOW, screen.getbkgd())
        self.blue_text = curses.color_pair(1) | curses.A_BOLD
        self.yellow_text = curses.color_pair(2) | curses.A_BOLD

        while True:
            # catch the exception when screen size is smaller than
            # the text length
            try:
                is_done = self.display_info(screen, info)
                if is_done:
                    return
            except curses.error:
                pass

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
            screen.addstr(start_row_num, start_col, resource,
                          self.yellow_text)

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
        screen.addstr(6, max_window_length - 30, "|" + "_"*29)

        # make Deauthenticating clients to blue color
        # print the deauthentication section
        screen.addstr(1, 0, "Deauthenticating clients: ",
                      self.blue_text)

        if info.em:
            # start raw number from 2
            raw_num = 2
            for client in info.em.get_output()[-5:]:
                screen.addstr(raw_num, 0, client)
                raw_num += 1

        # print the dhcp lease section
        screen.addstr(7, 0, "DHCP Leases", self.blue_text)
        if os.path.isfile('/var/lib/misc/dnsmasq.leases'):
            dnsmasq_output = check_output(['tail', '-5',
                                           '/var/lib/misc/dnsmasq.leases'])
            screen.addstr(8, 0, dnsmasq_output)

        # print the http request section
        screen.addstr(13, 0, "HTTP requests: ", self.blue_text)
        if os.path.isfile('/tmp/wifiphisher-webserver.tmp'):
            http_output = check_output(['tail', '-5',
                                        '/tmp/wifiphisher-webserver.tmp'])
            self.print_http_requests(screen, 14, http_output)

        # detect if users have pressed the Esc Key
        if screen.getch() == 27:
            is_done = True

        if info.phishinghttp.terminate and info.args.quitonsuccess:
            is_done = True

        screen.refresh()
        return is_done


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
    return (" ".join(pieces[i:i+num_of_words])
            for i in xrange(0, len(pieces), num_of_words))
