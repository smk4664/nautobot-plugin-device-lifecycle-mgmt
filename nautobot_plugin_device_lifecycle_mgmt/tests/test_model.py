"""nautobot_plugin_device_lifecycle_mgmt test class for models."""
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.conf import settings

from nautobot.dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site

from nautobot_plugin_device_lifecycle_mgmt.models import HardwareLCM


class TestModelBasic(TestCase):
    """Tests for the HardwareLCM models."""

    def setUp(self):
        """Set up base objects."""
        self.manufacturer = Manufacturer.objects.create(name="Cisco")
        self.device_type = DeviceType.objects.create(model="c9300-24", slug="c9300-24", manufacturer=self.manufacturer)

    def test_create_hwlcm_success_eo_sale(self):
        """Successfully create basic notice with end_of_sale."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_sale="2023-04-01")

        self.assertEqual(hwlcm_obj.device_type, self.device_type)
        self.assertEqual(str(hwlcm_obj.end_of_sale), "2023-04-01")
        self.assertEqual(str(hwlcm_obj), "c9300-24 - End of sale: 2023-04-01")

    def test_create_hwlcm_notice_success_eo_support(self):
        """Successfully create basic notice with end_of_support."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_support="2022-04-01")

        self.assertEqual(hwlcm_obj.device_type, self.device_type)
        self.assertEqual(str(hwlcm_obj.end_of_support), "2022-04-01")
        self.assertEqual(str(hwlcm_obj), "c9300-24 - End of support: 2022-04-01")

    def test_create_hwlcm_notice_success_eo_all(self):
        """Successfully create basic notice."""
        hwlcm_obj = HardwareLCM.objects.create(
            device_type=self.device_type,
            end_of_sale="2022-04-01",
            end_of_support="2023-04-01",
            end_of_sw_releases="2024-04-01",
            end_of_security_patches="2025-04-01",
            documentation_url="https://test.com",
        )

        self.assertEqual(hwlcm_obj.device_type, self.device_type)
        self.assertEqual(str(hwlcm_obj.end_of_sale), "2022-04-01")
        self.assertEqual(str(hwlcm_obj.end_of_support), "2023-04-01")
        self.assertEqual(str(hwlcm_obj.end_of_sw_releases), "2024-04-01")
        self.assertEqual(str(hwlcm_obj.end_of_security_patches), "2025-04-01")
        self.assertEqual(hwlcm_obj.documentation_url, "https://test.com")
        self.assertEqual(str(hwlcm_obj), "c9300-24 - End of support: 2023-04-01")

    def test_create_hwlcm_notice_failed_missing_one_of(self):
        """Successfully create basic notice."""
        with self.assertRaises(ValidationError) as failure_exception:
            HardwareLCM.objects.create(device_type=self.device_type)
        self.assertEqual(failure_exception.exception.messages[0], "End of Sale or End of Support must be specified.")

    def test_create_hwlcm_notice_failed_validation_documentation_url(self):
        """Successfully create basic notice."""
        with self.assertRaises(ValidationError) as failure_exception:
            HardwareLCM.objects.create(
                device_type=self.device_type, end_of_support="2023-04-01", documentation_url="test.com"
            )
        self.assertEqual(failure_exception.exception.messages[0], "Enter a valid URL.")

    def test_create_hwlcm_notice_failed_validation_date(self):
        """Successfully create basic notice."""
        with self.assertRaises(ValidationError) as failure_exception:
            HardwareLCM.objects.create(device_type=self.device_type, end_of_support="April 1st 2022")
        self.assertIn("invalid date format. It must be in YYYY-MM-DD format.", failure_exception.exception.messages[0])

    def test_create_hwlcm_notice_check_devices(self):
        """Successfully create notice and assert correct amount of devices attached."""
        # Create Device dependencies
        site = Site.objects.create(name="Test Site")
        device_role = DeviceRole.objects.create(name="Core Switch")

        # Create 4 devices to assert they get attached to HardwareLCM
        for i in range(0, 4):
            Device.objects.create(name=f"r{i}", site=site, device_role=device_role, device_type=self.device_type)

        # Create Notice now
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_support="2022-04-01")
        self.assertEqual(hwlcm_obj.device_type, self.device_type)
        self.assertEqual(str(hwlcm_obj.end_of_support), "2022-04-01")
        self.assertEqual(str(hwlcm_obj), "c9300-24 - End of support: 2022-04-01")
        self.assertEqual(hwlcm_obj.devices.count(), 4)

    def test_expired_property_end_of_support_expired(self):
        """Test expired property is expired with end_of_support."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_support="2021-04-01")
        self.assertTrue(hwlcm_obj.expired)

    def test_expired_property_end_of_support_not_expired(self):
        """Test expired property is NOT expired with end_of_support."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_support="2999-04-01")
        self.assertFalse(hwlcm_obj.expired)

    def test_expired_property_end_of_sale_expired(self):
        """Test expired property is expired with end_of_sale."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_sale="2021-04-01")
        self.assertTrue(hwlcm_obj.expired)

    def test_expired_property_end_of_sale_not_expired(self):
        """Test expired property is NOT expired with end_of_sale."""
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_sale="2999-04-01")
        self.assertFalse(hwlcm_obj.expired)

    def test_expired_field_setting_end_of_sale_expired(self):
        """Test expired property is expired with end_of_sale when set within plugin settings."""
        settings.PLUGINS_CONFIG["nautobot_plugin_device_lifecycle_mgmt"]["expired_field"] = "end_of_sale"
        hwlcm_obj = HardwareLCM.objects.create(
            device_type=self.device_type, end_of_sale="2021-04-01", end_of_support="2999-04-01"
        )
        self.assertTrue(hwlcm_obj.expired)

    def test_expired_field_setting_end_of_sale_not_expired(self):
        """Test expired property is NOT expired with end_of_sale not existing but plugin setting set to end_of_sale."""
        settings.PLUGINS_CONFIG["nautobot_plugin_device_lifecycle_mgmt"]["expired_field"] = "end_of_sale"
        hwlcm_obj = HardwareLCM.objects.create(device_type=self.device_type, end_of_support="2999-04-01")
        self.assertFalse(hwlcm_obj.expired)