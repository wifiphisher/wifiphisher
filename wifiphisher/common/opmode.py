"""
All logic regarding the Operation Modes (opmodes).

The opmode is defined based on the user's arguments and the available
resources of the host system
"""
import argparse
import logging
import os
import sys

import pyric
import wifiphisher.common.constants as constants
import wifiphisher.common.interfaces as interfaces
import wifiphisher.extensions.handshakeverify as handshakeverify

logger = logging.getLogger(__name__)


class OpMode(object):
    """
    Manager of the operation mode
    """

    def __init__(self):
        """
        Construct the class
        :param self: An OpMode object
        :type self: OpMode
        :return: None
        :rtype: None
        """

        self.op_mode = 0x0
        # True if the system only contains one phy interface
        # or if the user wants us to use only one phy
        # e.g. using the --interface option
        self._use_one_phy = False
        # The card which supports monitor and ap mode
        self._perfect_card = None

    def initialize(self, args):
        """
        Initialize the opmode manager
        :param self: An OpMode object
        :param args: An argparse.Namespace object
        :type self: OpMode
        :type args: argparse.Namespace
        :return: None
        :rtype: None
        """

        self._perfect_card, self._use_one_phy =\
            interfaces.is_add_vif_required(args)
        self._check_args(args)

    def _check_args(self, args):
        """
        Checks the given arguments for logic errors.
        :param self: An OpMode object
        :param args: An argparse.Namespace object
        :type self: OpMode
        :type args: argparse.Namespace
        :return: None
        :rtype: None
        """

        if args.presharedkey and \
            (len(args.presharedkey) < 8 or
             len(args.presharedkey) > 64):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Pre-shared key must be between 8 and 63 printable'
                     'characters.')

        if args.handshake_capture and not os.path.isfile(
                args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Handshake capture does not exist.')
        elif args.handshake_capture and not handshakeverify.\
                is_valid_handshake_capture(args.handshake_capture):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Handshake capture does not contain valid handshake')

        if ((args.extensionsinterface and not args.apinterface) or
                (not args.extensionsinterface and args.apinterface)) and \
                not (args.noextensions and args.apinterface):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --apinterface (-aI) and --extensionsinterface (-eI)'
                     '(or --noextensions (-nE)) are used in conjuction.')

        if args.noextensions and args.extensionsinterface:
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --noextensions (-nE) and --extensionsinterface (-eI)'
                     'cannot work together.')

        if args.lure10_exploit and args.noextensions:
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] --lure10-exploit (-lE) and --noextensions (-eJ)'
                     'cannot work together.')

        if args.lure10_exploit and not os.path.isfile(constants.LOCS_DIR +
                                                      args.lure10_exploit):
            sys.exit('[' + constants.R + '-' + constants.W +
                     '] Lure10 capture does not exist. Listing directory'
                     'of captures: ' + str(os.listdir(constants.LOCS_DIR)))

        if (args.mac_ap_interface and args.no_mac_randomization) or \
                (args.mac_extensions_interface and args.no_mac_randomization):
            sys.exit(
                '[' + constants.R + '-' + constants.W +
                '] --no-mac-randomization (-iNM) cannot work together with'
                '--mac-ap-interface or --mac-extensions-interface (-iDM)')

        if args.deauth_essid and args.noextensions:
            sys.exit(
                '[' + constants.R + '-' + constants.W +
                '] --deauth-essid (-dE) cannot work together with'
                '--noextension (-nE)')

        # if args.deauth_essid is set we need the second card to
        # do the frequency hopping
        if args.deauth_essid and self._use_one_phy:
            print(('[' + constants.R + '!' + constants.W +
                  '] Only one card was found. Wifiphisher will deauth only '
                  'on the target AP channel'))

        # args.wAI should be used with args.wE
        if args.wpspbc_assoc_interface and not args.wps_pbc:
            sys.exit(
                '[' + constants.R + '!' + constants.W +
                '] --wpspbc-assoc-interface (-wAI) requires --wps-pbc (-wP) option.'
            )

        # if args.logpath is defined args.logging must be set too
        if args.logpath and not args.logging:
            sys.exit(
                '[' + constants.R + '!' + constants.W +
                '] --logpath (-lP) requires --logging option.'
            )

        # if args.credential_log_path is defined args.logging must be set too
        if args.credential_log_path and not args.logging:
            sys.exit(
                '[' + constants.R + '!' + constants.W +
                '] --credential-log-path (-cP) requires --logging option.'
            )

        if args.deauth_channels:
            for channel in args.deauth_channels:
                if channel > 14 or channel < 0:
                    sys.exit(
                        '[' + constants.R + '!' + constants.W +
                        '] --deauth-channels (-dC) requires channels in range 1-14.'
                    )

    def set_opmode(self, args, network_manager):
        """
        Sets the operation mode.

        :param self: An OpMode object
        :param args: An argparse.Namespace object
        :param network_manager: A NetworkManager object
        :type self: OpMode
        :type args: argparse.Namespace
        :type network_manager: NetworkManager
        :return: None
        :rtype: None

        ..note: An operation mode resembles how the tool will best leverage
        the given resources.

        Modes of operation
        1) AP and Extensions 0x1
          2 cards, 2 interfaces
          i) AP, ii) EM
          Channel hopping: Enabled
        2) AP, Extensions and Internet 0x2
          3 cards, 3 interfaces
          i) AP, ii) EM iii) Internet
          Channel hopping: Enabled
        3) AP-only and Internet 0x3
          2 cards, 2 interfaces
          i) AP, ii) Internet
        4) AP-only 0x4
          1 card, 1 interface
          i) AP
        5) AP and Extensions 0x5
          1 card, 2 interfaces
          (1 card w/ vif support AP/Monitor)
          i) AP, ii) Extensions
          Channel hopping: Disabled
          !!Most common mode!!
        6) AP and Extensions and Internet 0x6
          2 cards, 3 interfaces
          Channel hopping: Disabled
          (Internet and 1 card w/ 1 vif support AP/Monitor)
          i) AP, ii) Extensions, iii) Internet
        7) Advanced and WPS association 0x7
          3 cards, 3 interfaces
          i) AP, ii) Extensions (Monitor), iii) Extensions (Managed)
        8) Advanced and WPS association w/ 1 vif support AP/Monitor 0x8
          2 cards, 3 interfaces
          i) AP, ii) Extensions (Monitor), iii) Extensions (Managed)
        """

        if not args.internetinterface and not args.noextensions:
            if not self._use_one_phy:
                # check if there is WPS association interface
                if args.wpspbc_assoc_interface:
                    self.op_mode = constants.OP_MODE7
                    logger.info("Starting OP_MODE7 (0x7)")
                else:
                    self.op_mode = constants.OP_MODE1
                    logger.info("Starting OP_MODE1 (0x1)")
            else:
                # TODO: We should not add any vifs here.
                # These should happen after the interface 
                # checks in main engine
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                # check if there is WPS association interface
                if args.wpspbc_assoc_interface:
                    self.op_mode = constants.OP_MODE8
                    logger.info("Starting OP_MODE8 (0x8)")
                else:
                    self.op_mode = constants.OP_MODE5
                    logger.info("Starting OP_MODE5 (0x5)")
        if args.internetinterface and not args.noextensions:
            if not self._use_one_phy:
                self.op_mode = constants.OP_MODE2
                logger.info("Starting OP_MODE2 (0x2)")
            else:
                if self._perfect_card is not None:
                    network_manager.add_virtual_interface(self._perfect_card)
                self.op_mode = constants.OP_MODE6
                logger.info("Starting OP_MODE6 (0x6)")

        if args.internetinterface and args.noextensions:
            self.op_mode = constants.OP_MODE3
            logger.info("Starting OP_MODE3 (0x3)")
        if args.noextensions and not args.internetinterface:
            self.op_mode = constants.OP_MODE4
            logger.info("Starting OP_MODE4 (0x4)")

    def internet_sharing_enabled(self):
        """
        :param self: An OpMode object
        :type self: OpMode
        :return: True if we are operating in a mode that shares Internet
        access.
        :rtype: bool
        """

        return self.op_mode in [constants.OP_MODE2, constants.OP_MODE3,
                                constants.OP_MODE6]

    def extensions_enabled(self):
        """
        :param self: An OpModeManager object
        :type self: OpModeManager
        :return: True if we are loading extensions
        :rtype: bool
        """

        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE5,
            constants.OP_MODE6, constants.OP_MODE7, constants.OP_MODE8
        ]

    def freq_hopping_enabled(self):
        """
        :param self: An OpMode object
        :type self: OpMode
        :return: True if we are separating the wireless cards
        for extensions and launching AP.
        :rtype: bool
        ..note: MODE5 and MODE6 only use one card to do deauth and
        lunch ap so it is not allowed to do frequency hopping.
        """

        return self.op_mode in [
            constants.OP_MODE1, constants.OP_MODE2, constants.OP_MODE7
        ]

    def assoc_enabled(self):
        """
        :param self: An OpMode object
        :type self: OpMode
        :return: True if we are using managed Extensions(that associate to WLANs)
        :rtype: bool
        """
        return self.op_mode in [constants.OP_MODE7, constants.OP_MODE8]


def validate_ap_interface(interface):
    """
    Validate the given interface

    :param interface: Name of an interface
    :type interface: str
    :return: the ap interface
    :rtype: str
    :raises: argparse.ArgumentTypeError in case of invalid interface
    """

    if not(pyric.pyw.iswireless(interface) and \
        pyric.pyw.isinterface(interface) and \
        interfaces.does_have_mode(interface, "AP")):

        raise argparse.ArgumentTypeError("Provided interface ({})"
                                         " either does not exist or"
                                         " does not support AP mode" \
                                        .format(interface))
    return interface
