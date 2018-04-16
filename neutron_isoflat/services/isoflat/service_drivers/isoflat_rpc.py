from oslo_log import log as logging

from neutron_isoflat.services.isoflat import service_drivers

LOG = logging.getLogger(__name__)


class IsoflatRpcDriver(service_drivers.IsoflatBaseDriver):

    def __init__(self, service_plugin):
        LOG.debug("Loading IsoflatRpcDriver.")
        super(IsoflatRpcDriver, self).__init__(service_plugin)

    @property
    def service_type(self):
        pass
