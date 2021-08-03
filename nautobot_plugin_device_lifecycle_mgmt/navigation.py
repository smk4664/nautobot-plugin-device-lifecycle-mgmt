"""Menu items."""
from packaging.version import Version
from nautobot import __version__
from nautobot.utilities.choices import ButtonColorChoices
from nautobot_plugin_device_lifecycle_mgmt.const import Permissions

if Version(__version__) >= Version("1.1.0a"):
    from nautobot.core.apps import NavMenuTab, NavMenuGroup, NavMenuItem, NavMenuButton

    menu_items = (
        NavMenuTab(
            name="Device LifeCycle",
            weight=600,
            groups=(
                NavMenuGroup(
                    name="Hardware Notices",
                    weight=100,
                    items=(
                        NavMenuItem(
                            link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_list",
                            name="Hardware Notices",
                            permissions=[
                                Permissions.HardwareLCM.Read,
                            ],
                            buttons=(
                                NavMenuButton(
                                    link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_add",
                                    title="Add",
                                    icon_class="mdi mdi-plus-thick",
                                    button_class=ButtonColorChoices.GREEN,
                                    permissions=[
                                        Permissions.HardwareLCM.Create,
                                    ],
                                ),
                                NavMenuButton(
                                    link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_import",
                                    title="Import",
                                    icon_class="mdi mdi-database-import-outline",
                                    button_class=ButtonColorChoices.BLUE,
                                    permissions=[
                                        Permissions.HardwareLCM.Create,
                                    ],
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
else:
    from nautobot.extras.plugins import PluginMenuItem, PluginMenuButton

    menu_items = (
        PluginMenuItem(
            link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_list",
            link_text="Hardware Notices",
            buttons=(
                PluginMenuButton(
                    link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_add",
                    title="Add",
                    icon_class="mdi mdi-plus-thick",
                    color=ButtonColorChoices.GREEN,
                    permissions=[Permissions.HardwareLCM.Create],
                ),
                PluginMenuButton(
                    link="plugins:nautobot_plugin_device_lifecycle_mgmt:hardwarelcm_import",
                    title="Import",
                    icon_class="mdi mdi-database-import-outline",
                    color=ButtonColorChoices.BLUE,
                    permissions=[Permissions.HardwareLCM.Create],
                ),
            ),
        ),
    )