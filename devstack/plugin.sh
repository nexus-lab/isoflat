#!/bin/bash

function install_isoflat {
    pip_install --no-deps --editable $ISOFLAT_PLUGIN_PATH
}

function configure_isoflat_plugin {
    cp $ISOFLAT_PLUGIN_PATH/etc/isoflat.ini $ISOFLAT_PLUGIN_CONF_FILE
    neutron_server_config_add $ISOFLAT_PLUGIN_CONF_FILE
    neutron_service_plugin_class_add isoflat
}

if is_service_enabled isoflat; then
    if [[ "$1" == "stack" ]]; then
        if [[ "$2" == "pre-install" ]]; then
            :
        elif [[ "$2" == "install" ]]; then
            install_isoflat
        elif [[ "$2" == "post-config" ]]; then
            configure_isoflat_plugin
            neutron-db-manage --subproject isoflat upgrade head
            echo "Configuring isoflat"
            if [ "$ISOFLAT_SERVICE_DRIVER" ]; then
                inicomment $ISOFLAT_PLUGIN_CONF_FILE service_providers service_provider
                iniadd $ISOFLAT_PLUGIN_CONF_FILE service_providers service_provider $ISOFLAT_SERVICE_DRIVER
            fi
        elif [[ "$2" == "extra" ]]; then
            :
        fi
    elif [[ "$1" == "unstack" ]]; then
        :
    fi
fi

if is_service_enabled q-agt neutron-agent; then
    if [[ "$1" == "stack" ]]; then
        if [[ "$2" == "pre-install" ]]; then
            :
        elif [[ "$2" == "install" ]]; then
            install_isoflat
        elif [[ "$2" == "post-config" ]]; then
            if is_service_enabled q-agt neutron-agent; then
                source $NEUTRON_DIR/devstack/lib/l2_agent
                plugin_agent_add_l2_agent_extension isoflat
                configure_l2_agent
            fi
        elif [[ "$2" == "extra" ]]; then
            :
        fi
    elif [[ "$1" == "unstack" ]]; then
        :
    fi
fi
