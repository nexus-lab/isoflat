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
            if [[ ! -f $ISOFLAT_PLUGIN_CONF_FILE ]]; then
                configure_isoflat_plugin
            fi
            if is_service_enabled q-agt neutron-agent; then
                source $NEUTRON_DIR/devstack/lib/l2_agent
                plugin_agent_add_l2_agent_extension isoflat
                configure_l2_agent
                neutron_deploy_rootwrap_filters $ISOFLAT_PLUGIN_PATH
            fi
        elif [[ "$2" == "extra" ]]; then
            if is_service_enabled q-agt; then
                stop_process q-agt
                run_process q-agt "$AGENT_BINARY --config-file $NEUTRON_CONF --config-file /$Q_PLUGIN_CONF_FILE --config-file $ISOFLAT_AGENT_CONF_FILE"
            elif is_service_enabled neutron-agent; then
                stop_process neutron-agent
                run_process neutron-agent "$NEUTRON_BIN_DIR/$NEUTRON_AGENT_BINARY --config-file $NEUTRON_CONF --config-file $NEUTRON_CORE_PLUGIN_CONF --config-file $ISOFLAT_AGENT_CONF_FILE"
            fi
        fi
    elif [[ "$1" == "unstack" ]]; then
        :
    fi
fi
