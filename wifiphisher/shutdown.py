""" This module will handle all the shutdown process """


class ShutDown(object):
    """ Handle all the shutdown process """

    def __init__(self):
        """
        Setup the class with all the given arguments

        :param self: A ShutDown object
        :type self: ShutDown
        :return: None
        :rtype: None
        """

        self._objects = list()

    def shut_down(self):
        """
        Stop all the added objects

        :param self: A ShutDown object
        :type self: ShutDown
        :return: None
        :rtype: None
        """

        for _object in self._objects:
            _object.stop()

    def add_object(self, _object):
        """
        Add an object to the object list to be ShutDown

        :param self: A ShutDown object
        :param _object: An object to be shutdown
        :type self: ShutDown
        :type _object: Any python object
        :return: None
        :rtype: None
        .. warning: _object must have a stop method
        """

        self._objects.append(_object)
