import abc

import six


@six.add_metaclass(abc.ABCMeta)
class IsoflatBaseDriver(object):

    def __init__(self, service_plugin):
        self.service_plugin = service_plugin

    @property
    def service_type(self):
        pass
