"""
Azure Automation documentation : https://aka.ms/azure-automation-python-documentation
Azure Python SDK documentation : https://aka.ms/azure-python-sdk
"""


import os
from azure.mgmt.compute import ComputeManagementClient
import azure.mgmt.resource
import automationassets

import sys

# resource_group_name = str(sys.argv[1])
# vm_name = str(sys.argv[2])

def get_automation_runas_credential(runas_connection):
    from OpenSSL import crypto
    import binascii
    from msrestazure import azure_active_directory
    import adal

    # Get the Azure Automation RunAs service principal certificate
    cert = automationassets.get_automation_certificate("AzureRunAsCertificate")
    pks12_cert = crypto.load_pkcs12(cert)
    pem_pkey = crypto.dump_privatekey(crypto.FILETYPE_PEM,pks12_cert.get_privatekey())

    # Get run as connection information for the Azure Automation service principal
    application_id = runas_connection["ApplicationId"]
    thumbprint = runas_connection["CertificateThumbprint"]
    tenant_id = runas_connection["TenantId"]

    # Authenticate with service principal certificate
    resource ="https://management.core.windows.net/"
    authority_url = ("https://login.microsoftonline.com/"+tenant_id)
    context = adal.AuthenticationContext(authority_url)
    return azure_active_directory.AdalAuthentication(
    lambda: context.acquire_token_with_client_certificate(
            resource,
            application_id,
            pem_pkey,
            thumbprint)
    )

# Authenticate to Azure using the Azure Automation RunAs service principal
runas_connection = automationassets.get_automation_connection("AzureRunAsConnection")
azure_credential = get_automation_runas_credential(runas_connection)



from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.common.client_factory import get_client_from_cli_profile

# Azure Datacenter
LOCATION = 'eastus'

# Resource Group
GROUP_NAME = 'python_test_rg'

# Network
VNET_NAME = 'azure-sample-vnet'
SUBNET_NAME = 'azure-sample-subnet'


def create_nsg_parameters():
    """Create the VM parameters structure.
    """
    return {
        'id': None,
        'location': LOCATION,
        'tags': {
            'tag1': 'tag1',
            'tag2': 'tag2',
            'tag3': 'tag3'
        },
        'security_rules': [
          {
            # 'id': None,
            'description': "test rule",
            'protocol': 'TCP',
            'source_port_range': '*',
            'destination_port_range': "22",
            'source_address_prefix': '*',
            'destination_address_prefix': '*',
            'access': 'allow',
            'priority': "200",
            'direction': 'inbound',
            'name': 'test_rule_1'
          },
          {
              # 'id': None,
              'description': "Global rule",
              'protocol': 'TCP',
              'source_port_range': '*',
              'destination_port_range': "23",
              'source_address_prefix': '*',
              'destination_address_prefix': '*',
              'access': 'allow',
              'priority': "2000",
              'direction': 'inbound',
              'name': 'Glboal_Rule_00'
          },
          {
              # 'id': None,
              'description': "Global rule",
              'protocol': 'TCP',
              'source_port_range': '*',
              'destination_port_range': "24",
              'source_address_prefix': '*',
              'destination_address_prefix': '*',
              'access': 'allow',
              'priority': "2001",
              'direction': 'inbound',
              'name': 'Glboal_Rule_01'
          },
          {
              # 'id': None,
              'description': "Global rule",
              'protocol': 'TCP',
              'source_port_range': '*',
              'destination_port_range': "25",
              'source_address_prefix': '*',
              'destination_address_prefix': '*',
              'access': 'allow',
              'priority': "2002",
              'direction': 'inbound',
              'name': 'Glboal_Rule_02'
          },
          {
              # 'id': None,
              'description': "Global rule",
              'protocol': 'TCP',
              'source_port_range': '*',
              'destination_port_range': "26",
              'source_address_prefix': '*',
              'destination_address_prefix': '*',
              'access': 'allow',
              'priority': "2003",
              'direction': 'inbound',
              'name': 'Glboal_Rule_03'
          },

        ]
    }

def run_example():
  # Create client connetion
  print("Creating client connection...")
  network_client = NetworkManagementClient(
    azure_credential,
    str(runas_connection["SubscriptionId"])
  )
  print("Done")

  print("Updating NSG...")
  nsg_parameters = create_nsg_parameters()
  network_client.network_security_groups.create_or_update(
      GROUP_NAME, 'sample_nsg', nsg_parameters)
  print("Done")

if __name__ == "__main__":
    run_example()

