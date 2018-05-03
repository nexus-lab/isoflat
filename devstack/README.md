========================
DevStack external plugin
========================

A `local.conf` recipe to enable isoflat:

    [[local|localrc]]
    enable_plugin isoflat https://github.com/ppoffice/isoflat
    enable_service isoflat
    ISOFLAT_SERVICE_DRIVER=ISOFLAT:ISOFLAT:neutron_isoflat.services.isoflat.service_drivers.isoflat_rpc.IsoflatRpcDriver:default
