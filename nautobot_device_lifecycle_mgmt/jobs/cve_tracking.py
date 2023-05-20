"""Jobs for the CVE Tracking portion of the Device Lifecycle plugin."""
from datetime import datetime
import os
import openai
import requests
from openVulnQuery import query_client

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType

from nautobot.dcim.models import Platform
from nautobot.extras.jobs import Job, JobHookReceiver , StringVar, BooleanVar
from nautobot.extras.models import Relationship, RelationshipAssociation, Note

from nautobot_device_lifecycle_mgmt.models import (
    CVELCM,
    SoftwareLCM,
    VulnerabilityLCM,
)

# Use the proper swappable User model
User = get_user_model()

name = "CVE Tracking"  # pylint: disable=invalid-name


class GenerateVulnerabilities(Job):
    """Generates VulnerabilityLCM objects based on CVEs that are related to Devices."""

    name = "Generate Vulnerabilities"
    description = "Generates any missing Vulnerability objects."
    read_only = False
    published_after = StringVar(
        regex=r"^[0-9]{4}\-[0-9]{2}\-[0-9]{2}$",
        label="CVEs Published After",
        description="Enter a date in ISO Format (YYYY-MM-DD) to only process CVEs published after that date.",
        default="1970-01-01",
        required=False,
    )

    class Meta:  # pylint: disable=too-few-public-methods
        """Meta class for the job."""

        commit_default = True
        field_order = ["published_after", "_task_queue", "debug", "_commit"]

    debug = BooleanVar(description="Enable for more verbose logging.")

    def run(self, data, commit):  # pylint: disable=too-many-locals
        """Check if software assigned to each device is valid. If no software is assigned return warning message."""
        # Although the default is set on the class attribute for the UI, it doesn't default for the API
        published_after = data.get("published_after", "1970-01-01")
        cves = CVELCM.objects.filter(published_date__gte=datetime.fromisoformat(published_after))
        count_before = VulnerabilityLCM.objects.count()

        for cve in cves:
            if data["debug"]:
                self.log_info(obj=cve, message="Generating vulnerabilities for CVE {cve}")
            software_rels = RelationshipAssociation.objects.filter(relationship__slug="soft_cve", destination_id=cve.id)
            for soft_rel in software_rels:

                # Loop through any device relationships
                device_rels = soft_rel.source.get_relationships()["source"][
                    Relationship.objects.get(slug="device_soft")
                ]
                for dev_rel in device_rels:
                    vuln_obj, _ = VulnerabilityLCM.objects.get_or_create(
                        cve=cve, software=dev_rel.source, device=dev_rel.destination
                    )
                    vuln_obj.validated_save()

                # Loop through any inventory tem relationships
                item_rels = soft_rel.source.get_relationships()["source"][
                    Relationship.objects.get(slug="inventory_item_soft")
                ]
                for item_rel in item_rels:
                    vuln_obj, _ = VulnerabilityLCM.objects.get_or_create(
                        cve=cve, software=item_rel.source, inventory_item=item_rel.destination
                    )
                    vuln_obj.validated_save()

        diff = VulnerabilityLCM.objects.count() - count_before
        self.log_success(message=f"Processed {cves.count()} CVEs and generated {diff} Vulnerabilities.")


class CVEChatGPTJobHookReceiver(JobHookReceiver):
    class Meta:
        name = "CVE ChatGPT job hook receiver"
        description = "Use ChatGPT to retrieve CVE Remediation."

    def receive_job_hook(self, change, action, changed_object):
        # validate changes to serial field
        cve = changed_object
        # Get CVE data from NIST.
        response = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": cve.name},
            timeout=60,
        ).json()
        cve_data = response["vulnerabilities"][0]
        description = cve_data["cve"]["descriptions"][0]["value"]
        if not cve.published_date:
            cve.published_date = datetime.fromisoformat(cve_data["cve"]["published"]).date()
            cve.save()
        if not cve.link:
            cve.link = f"https://nvd.nist.gov/vuln/detail/{cve.name}"
            cve.save()
        if not cve.comments:
            cve.comments = description
            cve.save()
        try:
            cvss_score = cve_data["cve"]["evaluatorImpact"]
        except Exception as e:
            cvss_score = cve_data["cve"]["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]

        if not cve.cvss_v3:
            cve.cvss_v3 = cvss_score
            cve.save()

        cvss_score = cve.cvss_v3 or cve.cvss_v2
        prompt = f"Act as an expert Systems and Network Operator of a large enterprise. Given the following CVE: {cve.name}, with a description of {description} and a CVSS score of {cvss_score}. You are required to provide a report that includes: Impact Analysis and Action plan which includes a bullet list of software versions that address the specific vulnerability (if known). The report should be based on the specific info provided (not generic responses)."

        ai_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
        )

        ai_user, _ = User.objects.get_or_create(username="AI")

        Note.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(CVELCM),
            assigned_object_id=cve.pk,
            user=ai_user,
            note=f"{ai_response.choices[0].message.content}"
        )

        # Get Affected Versions from PSIRT
        psirt_query = query_client.OpenVulnQueryClient(
                client_id=os.environ.get("PSIRT_CLIENT_ID"),
                client_secret=os.environ.get("PSIRT_CLIENT_SECRET"),
            )
        psirt_advisory = psirt_query.get_by_cve(cve_id=cve.name, adv_format="ios")
        affected_versions = psirt_advisory[0].product_names

        # Add spaces for Markdown
        newline = '  \n'
        Note.objects.create(
            assigned_object_type=ContentType.objects.get_for_model(CVELCM),
            assigned_object_id=cve.pk,
            user=ai_user,
            note=f"Impacted Versions:  \n{newline.join(affected_versions)}"
        )

        # Create platform map for each of the affected versions.
        platform_map = {
            "ios": [],
            "ios_xe": [],
        }
        for version in affected_versions:
            if "Cisco IOS XE Software" in version:
                version_num = version.replace("Cisco IOS XE Software ", "")
                platform_map["ios_xe"].append(version_num)
            else:
                version_num = version.replace("Cisco IOS ", "")
                platform_map["ios"].append(version_num)

        soft_cve = Relationship.objects.get(slug="soft_cve")
        software_type = ContentType.objects.get_for_model(SoftwareLCM)
        cve_type = ContentType.objects.get_for_model(CVELCM)

        if platform_map.get("ios"):
            platform = Platform.objects.get(name="Cisco IOS")
            ios_objects = SoftwareLCM.objects.filter(device_platform=platform, version__in=platform_map.get("ios")).values_list("pk", flat=True)
            for pk in ios_objects:
                RelationshipAssociation.objects.create(
                    relationship=soft_cve,
                    source_type=software_type,
                    source_id=pk,
                    destination_type=cve_type,
                    destination_id=cve.pk
                )
        if platform_map.get("ios_xe"):
            platform = Platform.objects.get(name="Cisco IOS XE")
            ios_objects = SoftwareLCM.objects.filter(device_platform=platform, version__in=platform_map.get("ios_xe")).values_list("pk", flat=True)
            for pk in ios_objects:
                RelationshipAssociation.objects.create(
                    relationship=soft_cve,
                    source_type=software_type,
                    source_id=pk,
                    destination_type=cve_type,
                    destination_id=cve.pk
                )

        self.log_success(message=f"{cve.name} found for {cve}, message: {ai_response.choices[0].message.content}")
