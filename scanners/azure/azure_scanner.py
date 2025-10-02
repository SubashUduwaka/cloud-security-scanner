import logging
import json
from datetime import datetime, timezone
from functools import partial
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
from azure.mgmt.web import WebSiteManagementClient
from azure.core.exceptions import AzureError, HttpResponseError
from azure.mgmt.subscription import SubscriptionClient

# Additional Azure management clients for comprehensive scanning (optional)
# These imports are optional - if not available, we'll skip those specific scans
try:
    from azure.mgmt.containerinstance import ContainerInstanceManagementClient
    CONTAINERINSTANCE_AVAILABLE = True
except ImportError:
    CONTAINERINSTANCE_AVAILABLE = False
    logging.warning("azure.mgmt.containerinstance not available - skipping container instance scans")

try:
    from azure.mgmt.containerservice import ContainerServiceClient
    CONTAINERSERVICE_AVAILABLE = True
except ImportError:
    CONTAINERSERVICE_AVAILABLE = False
    logging.warning("azure.mgmt.containerservice not available - skipping container service scans")

try:
    from azure.mgmt.cosmosdb import CosmosDBManagementClient
    COSMOSDB_AVAILABLE = True
except ImportError:
    COSMOSDB_AVAILABLE = False
    logging.warning("azure.mgmt.cosmosdb not available - skipping Cosmos DB scans")

try:
    from azure.mgmt.redis import RedisManagementClient
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logging.warning("azure.mgmt.redis not available - skipping Redis cache scans")

try:
    from azure.mgmt.servicebus import ServiceBusManagementClient
    SERVICEBUS_AVAILABLE = True
except ImportError:
    SERVICEBUS_AVAILABLE = False
    logging.warning("azure.mgmt.servicebus not available - skipping Service Bus scans")

try:
    from azure.mgmt.eventhub import EventHubManagementClient
    EVENTHUB_AVAILABLE = True
except ImportError:
    EVENTHUB_AVAILABLE = False
    logging.warning("azure.mgmt.eventhub not available - skipping Event Hub scans")

# For the remaining imports, we'll use a simpler approach
OPTIONAL_MODULES = [
    'azure.mgmt.iothub', 'azure.mgmt.cdn', 'azure.mgmt.dns', 'azure.mgmt.trafficmanager',
    'azure.mgmt.applicationinsights', 'azure.mgmt.loganalytics', 'azure.mgmt.recoveryservices',
    'azure.mgmt.recoveryservicesbackup', 'azure.mgmt.automation', 'azure.mgmt.batch',
    'azure.mgmt.datafactory', 'azure.mgmt.datalake.store', 'azure.mgmt.hdinsight',
    'azure.mgmt.devtestlabs', 'azure.mgmt.apimanagement', 'azure.mgmt.search',
    'azure.mgmt.cognitiveservices', 'azure.mgmt.machinelearningservices', 'azure.mgmt.synapse',
    'azure.mgmt.purview', 'azure.mgmt.frontdoor', 'azure.mgmt.authorization'
]

# Try to import the remaining modules, but continue if they fail
for module_name in OPTIONAL_MODULES:
    try:
        globals()[module_name.split('.')[-1]] = __import__(module_name, fromlist=[''])
    except ImportError:
        logging.warning(f"{module_name} not available - some Azure scans will be skipped")

DEFAULT_AGE_DAYS = 90

def validate_azure_credentials(credential, subscription_id):
    """Validate Azure credentials and diagnose authentication issues"""
    validation_results = []

    try:
        from azure.mgmt.resource import ResourceManagementClient
        resource_client = ResourceManagementClient(credential, subscription_id)

        # Test basic authentication by listing resource groups
        try:
            resource_groups = list(resource_client.resource_groups.list())
            validation_results.append({
                "service": "Azure Auth Validation",
                "resource": "Credential Test",
                "status": "OK",
                "issue": f"Successfully authenticated. Found {len(resource_groups)} resource groups.",
                "remediation": "Credentials are working correctly."
            })
            logging.info(f"Azure credentials validated successfully. Found {len(resource_groups)} resource groups.")

        except Exception as rg_error:
            validation_results.append(handle_azure_exception(
                "Resource Groups",
                "list resource groups during validation",
                rg_error,
                "Failed to list resource groups. Check service principal has 'Reader' role on subscription."
            ))
            logging.error(f"Failed to list resource groups during validation: {rg_error}")

        # Test subscription access
        try:
            subscription = resource_client.subscriptions.get(subscription_id)
            validation_results.append({
                "service": "Azure Auth Validation",
                "resource": "Subscription Access",
                "status": "OK",
                "issue": f"Subscription access confirmed: {subscription.display_name}",
                "remediation": "Subscription access is working correctly."
            })
            logging.info(f"Subscription access confirmed: {subscription.display_name}")

        except Exception as sub_error:
            validation_results.append(handle_azure_exception(
                subscription_id,
                "access subscription during validation",
                sub_error,
                "Failed to access subscription. Verify subscription ID is correct and service principal has access."
            ))
            logging.error(f"Failed to access subscription during validation: {sub_error}")

    except Exception as e:
        validation_results.append(handle_azure_exception(
            "Azure Services",
            "initialize validation client",
            e,
            "Failed to initialize Azure clients. Check network connectivity and credential format."
        ))
        logging.error(f"Failed to initialize validation client: {e}")

    return validation_results

def handle_azure_exception(resource_name, action_desc, e, default_remediation="Check Azure permissions and connectivity."):
    """Helper function to create standardized error result with specific remediation advice."""
    issue = f"Could not perform {action_desc}."
    remediation = default_remediation

    # Log the full exception for debugging
    logging.error(f"Azure Exception Details - Resource: '{resource_name}', Action: '{action_desc}', Exception: {str(e)}, Type: {type(e).__name__}")

    if isinstance(e, HttpResponseError):
        status_code = e.status_code
        if status_code == 403:
            issue = f"Access denied for {action_desc}."
            remediation = f"Azure service principal lacks permissions. Grant 'Reader' role or higher for subscription/resource group '{resource_name}'. Check: https://portal.azure.com/#blade/Microsoft_Azure_AD/ActiveDirectoryMenuBlade/RegisteredApps"
        elif status_code == 401:
            issue = f"Authentication failed for {action_desc}."
            remediation = "Azure credentials are invalid or expired. Verify service principal client_id, client_secret, and tenant_id are correct."
        elif status_code == 404:
            issue = f"Resource '{resource_name}' not found or access denied."
            remediation = "Resource may not exist, be in different subscription, or service principal lacks access. Verify subscription ID and permissions."
        elif status_code == 429:
            issue = f"Rate limiting encountered for {action_desc}."
            remediation = "Azure API rate limit reached. Try again later or reduce request frequency."
        else:
            issue = f"HTTP {status_code} error for {action_desc}."
            remediation = f"Azure API returned HTTP {status_code}. Check Azure service status and credentials."
    elif "ClientAuthenticationError" in str(type(e)):
        issue = f"Authentication failed for {action_desc}."
        remediation = "Service principal credentials are invalid. Verify client_id, client_secret, tenant_id, and ensure service principal exists and is not expired."
    elif "ServiceRequestError" in str(type(e)):
        issue = f"Network error for {action_desc}."
        remediation = "Network connectivity issue or Azure service unavailable. Check internet connection and Azure status page."
    else:
        # Include more details for unknown errors
        issue = f"Could not perform {action_desc}: {str(e)[:100]}"
        remediation = f"Unknown error type: {type(e).__name__}. Check service principal permissions and Azure connectivity."

    logging.warning(f"Azure Exception for resource '{resource_name}' while trying to '{action_desc}': {issue}")
    return {"service": "Azure Scanner", "resource": resource_name, "status": "ERROR", "issue": issue, "remediation": remediation}


def scan_storage_account_encryption(storage_client, subscription_id):
    """Check if storage accounts have encryption enabled"""
    logging.debug("Starting scan: Storage Account Encryption")
    results = []
    
    try:
        # Get all resource groups first
        resource_client = ResourceManagementClient(storage_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                storage_accounts = list(storage_client.storage_accounts.list_by_resource_group(rg.name))
                
                for account in storage_accounts:
                    try:
                        # Check encryption settings
                        if account.encryption and account.encryption.services:
                            blob_encrypted = account.encryption.services.blob and account.encryption.services.blob.enabled
                            file_encrypted = account.encryption.services.file and account.encryption.services.file.enabled
                            
                            if blob_encrypted and file_encrypted:
                                results.append({
                                    "service": "Storage Account",
                                    "resource": account.name,
                                    "status": "OK",
                                    "issue": "Encryption is enabled for blob and file services.",
                                    "region": account.location
                                })
                            else:
                                results.append({
                                    "service": "Storage Account",
                                    "resource": account.name,
                                    "status": "CRITICAL",
                                    "issue": "Encryption is not fully enabled for all services.",
                                    "remediation": "Enable encryption for blob and file services in the Azure portal under Storage Account > Encryption settings.",
                                    "region": account.location,
                                    "doc_url": "https://docs.microsoft.com/en-us/azure/storage/common/storage-service-encryption"
                                })
                        else:
                            results.append({
                                "service": "Storage Account",
                                "resource": account.name,
                                "status": "CRITICAL",
                                "issue": "No encryption configuration found.",
                                "remediation": "Configure encryption for the storage account.",
                                "region": account.location
                            })
                    except Exception as e:
                        results.append(handle_azure_exception(account.name, "check encryption", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list storage accounts", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Storage Accounts", "list resource groups", e))
    
    return results


def scan_storage_account_public_access(storage_client, subscription_id):
    """Check if storage accounts allow public blob access"""
    logging.debug("Starting scan: Storage Account Public Access")
    results = []
    
    try:
        resource_client = ResourceManagementClient(storage_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                storage_accounts = list(storage_client.storage_accounts.list_by_resource_group(rg.name))
                
                for account in storage_accounts:
                    try:
                        if account.allow_blob_public_access is False:
                            results.append({
                                "service": "Storage Account",
                                "resource": account.name,
                                "status": "OK",
                                "issue": "Public blob access is disabled.",
                                "region": account.location
                            })
                        else:
                            results.append({
                                "service": "Storage Account",
                                "resource": account.name,
                                "status": "CRITICAL",
                                "issue": "Public blob access is enabled or not configured.",
                                "remediation": "Disable public blob access unless specifically required. Go to Storage Account > Configuration > Allow Blob public access.",
                                "region": account.location,
                                "doc_url": "https://docs.microsoft.com/en-us/azure/storage/blobs/anonymous-read-access-prevent"
                            })
                    except Exception as e:
                        results.append(handle_azure_exception(account.name, "check public access", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list storage accounts", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Storage Accounts", "list resource groups", e))
    
    return results


def scan_vm_managed_disks_encryption(compute_client, subscription_id):
    """Check if VM managed disks are encrypted"""
    logging.debug("Starting scan: VM Managed Disk Encryption")
    results = []
    
    try:
        resource_client = ResourceManagementClient(compute_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                vms = list(compute_client.virtual_machines.list(rg.name))
                
                for vm in vms:
                    try:
                        # Check OS disk encryption
                        if vm.storage_profile and vm.storage_profile.os_disk:
                            os_disk = vm.storage_profile.os_disk
                            if os_disk.encryption_settings and os_disk.encryption_settings.enabled:
                                results.append({
                                    "service": "Virtual Machine",
                                    "resource": f"{vm.name} (OS Disk)",
                                    "status": "OK",
                                    "issue": "OS disk encryption is enabled.",
                                    "region": vm.location
                                })
                            else:
                                results.append({
                                    "service": "Virtual Machine",
                                    "resource": f"{vm.name} (OS Disk)",
                                    "status": "HIGH",
                                    "issue": "OS disk encryption is not enabled.",
                                    "remediation": "Enable Azure Disk Encryption for VM disks using Azure Key Vault.",
                                    "region": vm.location,
                                    "doc_url": "https://docs.microsoft.com/en-us/azure/security/fundamentals/azure-disk-encryption-vms-vmss"
                                })
                        
                        # Check data disks
                        if vm.storage_profile and vm.storage_profile.data_disks:
                            for i, data_disk in enumerate(vm.storage_profile.data_disks):
                                if data_disk.encryption_settings and data_disk.encryption_settings.enabled:
                                    results.append({
                                        "service": "Virtual Machine",
                                        "resource": f"{vm.name} (Data Disk {i})",
                                        "status": "OK",
                                        "issue": "Data disk encryption is enabled.",
                                        "region": vm.location
                                    })
                                else:
                                    results.append({
                                        "service": "Virtual Machine",
                                        "resource": f"{vm.name} (Data Disk {i})",
                                        "status": "HIGH",
                                        "issue": "Data disk encryption is not enabled.",
                                        "remediation": "Enable Azure Disk Encryption for VM disks using Azure Key Vault.",
                                        "region": vm.location
                                    })
                                    
                    except Exception as e:
                        results.append(handle_azure_exception(vm.name, "check disk encryption", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list virtual machines", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Virtual Machines", "list resource groups", e))
    
    return results


def scan_network_security_groups(network_client, subscription_id):
    """Check Network Security Group rules for overly permissive access"""
    logging.debug("Starting scan: Network Security Groups")
    results = []
    
    try:
        resource_client = ResourceManagementClient(network_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                nsgs = list(network_client.network_security_groups.list(rg.name))
                
                for nsg in nsgs:
                    try:
                        # Check both default and custom security rules
                        all_rules = []
                        if nsg.security_rules:
                            all_rules.extend(nsg.security_rules)
                        if nsg.default_security_rules:
                            all_rules.extend(nsg.default_security_rules)
                        
                        risky_rules = []
                        for rule in all_rules:
                            if rule.access == 'Allow' and rule.direction == 'Inbound':
                                # Check for wildcard source addresses
                                source_addresses = rule.source_address_prefixes or [rule.source_address_prefix] if rule.source_address_prefix else []
                                
                                if any(addr in ['*', '0.0.0.0/0', 'Internet'] for addr in source_addresses):
                                    dest_ports = rule.destination_port_ranges or [rule.destination_port_range] if rule.destination_port_range else []
                                    
                                    # Check for sensitive ports
                                    sensitive_ports = ['22', '3389', '1433', '3306', '5432', '443', '80']
                                    for port_range in dest_ports:
                                        if any(port in str(port_range) for port in sensitive_ports):
                                            risky_rules.append(f"{rule.name} (Port: {port_range})")
                        
                        if risky_rules:
                            results.append({
                                "service": "Network Security Group",
                                "resource": nsg.name,
                                "status": "CRITICAL",
                                "issue": f"Overly permissive inbound rules found: {', '.join(risky_rules)}",
                                "remediation": "Restrict source IP ranges to specific networks. Avoid using wildcard (*) or 0.0.0.0/0 for sensitive ports.",
                                "region": nsg.location,
                                "doc_url": "https://docs.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview"
                            })
                        else:
                            results.append({
                                "service": "Network Security Group",
                                "resource": nsg.name,
                                "status": "OK",
                                "issue": "No overly permissive inbound rules detected.",
                                "region": nsg.location
                            })
                            
                    except Exception as e:
                        results.append(handle_azure_exception(nsg.name, "analyze security rules", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list network security groups", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Network Security Groups", "list resource groups", e))
    
    return results


def scan_sql_database_encryption(sql_client, subscription_id):
    """Check if SQL databases have Transparent Data Encryption enabled"""
    logging.debug("Starting scan: SQL Database Encryption")
    results = []
    
    try:
        resource_client = ResourceManagementClient(sql_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                sql_servers = list(sql_client.servers.list_by_resource_group(rg.name))
                
                for server in sql_servers:
                    try:
                        databases = list(sql_client.databases.list_by_server(rg.name, server.name))
                        
                        for db in databases:
                            if db.name.lower() == 'master':  # Skip master database
                                continue
                                
                            try:
                                # Check TDE status
                                tde_config = sql_client.transparent_data_encryptions.get(
                                    rg.name, server.name, db.name
                                )
                                
                                if tde_config.status == 'Enabled':
                                    results.append({
                                        "service": "SQL Database",
                                        "resource": f"{server.name}/{db.name}",
                                        "status": "OK",
                                        "issue": "Transparent Data Encryption (TDE) is enabled.",
                                        "region": server.location
                                    })
                                else:
                                    results.append({
                                        "service": "SQL Database",
                                        "resource": f"{server.name}/{db.name}",
                                        "status": "CRITICAL",
                                        "issue": "Transparent Data Encryption (TDE) is not enabled.",
                                        "remediation": "Enable TDE in Azure Portal under SQL Database > Security > Transparent data encryption.",
                                        "region": server.location,
                                        "doc_url": "https://docs.microsoft.com/en-us/azure/azure-sql/database/transparent-data-encryption-tde-overview"
                                    })
                            except Exception as e:
                                results.append(handle_azure_exception(f"{server.name}/{db.name}", "check TDE status", e))
                                
                    except Exception as e:
                        results.append(handle_azure_exception(server.name, "list databases", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list SQL servers", e))
                
    except Exception as e:
        results.append(handle_azure_exception("SQL Databases", "list resource groups", e))
    
    return results


def scan_key_vault_access_policies(keyvault_client, subscription_id):
    """Check Key Vault access policies for security"""
    logging.debug("Starting scan: Key Vault Access Policies")
    results = []
    
    try:
        resource_client = ResourceManagementClient(keyvault_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                key_vaults = list(keyvault_client.vaults.list_by_resource_group(rg.name))
                
                for kv in key_vaults:
                    try:
                        if kv.properties.access_policies:
                            risky_policies = []
                            
                            for policy in kv.properties.access_policies:
                                # Check for overly permissive permissions
                                all_permissions = []
                                if policy.permissions.keys:
                                    all_permissions.extend(policy.permissions.keys)
                                if policy.permissions.secrets:
                                    all_permissions.extend(policy.permissions.secrets)
                                if policy.permissions.certificates:
                                    all_permissions.extend(policy.permissions.certificates)
                                
                                dangerous_perms = ['all', 'purge', 'delete']
                                if any(perm.lower() in dangerous_perms for perm in all_permissions):
                                    risky_policies.append(str(policy.object_id)[:8] + "...")
                            
                            if risky_policies:
                                results.append({
                                    "service": "Key Vault",
                                    "resource": kv.name,
                                    "status": "HIGH",
                                    "issue": f"Found {len(risky_policies)} access policies with potentially dangerous permissions.",
                                    "remediation": "Review and restrict Key Vault access policies. Apply principle of least privilege.",
                                    "region": kv.location,
                                    "doc_url": "https://docs.microsoft.com/en-us/azure/key-vault/general/security-features"
                                })
                            else:
                                results.append({
                                    "service": "Key Vault",
                                    "resource": kv.name,
                                    "status": "OK",
                                    "issue": "Access policies appear to follow security best practices.",
                                    "region": kv.location
                                })
                        else:
                            results.append({
                                "service": "Key Vault",
                                "resource": kv.name,
                                "status": "MEDIUM",
                                "issue": "No access policies configured.",
                                "remediation": "Configure appropriate access policies for Key Vault.",
                                "region": kv.location
                            })
                            
                    except Exception as e:
                        results.append(handle_azure_exception(kv.name, "analyze access policies", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list key vaults", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Key Vaults", "list resource groups", e))
    
    return results


def scan_web_app_https_only(web_client, subscription_id):
    """Check if Web Apps enforce HTTPS only"""
    logging.debug("Starting scan: Web App HTTPS Configuration")
    results = []
    
    try:
        resource_client = ResourceManagementClient(web_client._credential, subscription_id)
        resource_groups = list(resource_client.resource_groups.list())
        
        for rg in resource_groups:
            try:
                web_apps = list(web_client.web_apps.list_by_resource_group(rg.name))
                
                for app in web_apps:
                    try:
                        if app.https_only:
                            results.append({
                                "service": "Web App",
                                "resource": app.name,
                                "status": "OK",
                                "issue": "HTTPS only is enforced.",
                                "region": app.location
                            })
                        else:
                            results.append({
                                "service": "Web App",
                                "resource": app.name,
                                "status": "CRITICAL",
                                "issue": "HTTPS only is not enforced, allowing insecure HTTP connections.",
                                "remediation": "Enable 'HTTPS Only' in App Service settings under TLS/SSL settings.",
                                "region": app.location,
                                "doc_url": "https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-bindings#enforce-https"
                            })
                            
                    except Exception as e:
                        results.append(handle_azure_exception(app.name, "check HTTPS configuration", e))
                        
            except Exception as e:
                results.append(handle_azure_exception(rg.name, "list web apps", e))
                
    except Exception as e:
        results.append(handle_azure_exception("Web Apps", "list resource groups", e))
    
    return results


def get_all_scan_functions(credentials, regions=None):
    """Return a list of (name, function) tuples for Azure security scans"""
    logging.info("Initializing Azure scan functions")
    
    functions_to_run = []
    
    try:
        # Extract Azure credentials
        subscription_id = credentials.get('azure_subscription_id')
        auth_data = credentials.get('azure_auth_data')
        
        if not subscription_id:
            raise ValueError("Azure subscription ID not provided")
        
        if not auth_data:
            raise ValueError("Azure authentication data not provided")
        
        # Initialize Azure credential object
        credential = None
        
        try:
            # Try to parse as Service Principal JSON
            auth_json = json.loads(auth_data)
            tenant_id = auth_json.get('tenant_id')
            client_id = auth_json.get('client_id')
            client_secret = auth_json.get('client_secret')

            if not tenant_id or not client_id or not client_secret:
                raise ValueError("Service principal JSON missing required fields: tenant_id, client_id, or client_secret")

            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            logging.info(f"Using Azure Service Principal authentication - Tenant: {tenant_id[:8]}..., Client: {client_id[:8]}...")

        except json.JSONDecodeError as je:
            logging.warning(f"Failed to parse Azure auth data as JSON: {je}. Attempting DefaultAzureCredential...")
            # If not JSON, use DefaultAzureCredential (for managed identity, CLI, etc.)
            credential = DefaultAzureCredential()
            logging.info("Using DefaultAzureCredential authentication")
        except ValueError as ve:
            logging.error(f"Invalid service principal configuration: {ve}")
            raise
        
        # Validate credentials first before proceeding
        logging.info("Validating Azure credentials before scanning...")
        validation_results = validate_azure_credentials(credential, subscription_id)

        # Check if validation passed
        validation_passed = any(result.get('status') == 'OK' for result in validation_results)

        if not validation_passed:
            logging.error("Azure credential validation failed. Returning validation errors.")
            functions_to_run.extend([
                ("Azure Credential Validation", lambda: validation_results)
            ])
            return functions_to_run

        # Initialize Azure clients only if validation passed
        storage_client = StorageManagementClient(credential, subscription_id)
        compute_client = ComputeManagementClient(credential, subscription_id)
        network_client = NetworkManagementClient(credential, subscription_id)
        sql_client = SqlManagementClient(credential, subscription_id)
        keyvault_client = KeyVaultManagementClient(credential, subscription_id)
        web_client = WebSiteManagementClient(credential, subscription_id)

        logging.info("Successfully initialized Azure clients for scanning")

        # Include validation results as first scan results
        functions_to_run.extend([
            ("Azure Credential Validation", lambda: validation_results)
        ])
        
        # Add only functions that are actually defined
        functions_to_run.extend([
            ("Azure Storage Account Encryption", partial(scan_storage_account_encryption, storage_client, subscription_id)),
            ("Azure Storage Account Public Access", partial(scan_storage_account_public_access, storage_client, subscription_id)),
            ("Azure VM Disk Encryption", partial(scan_vm_managed_disks_encryption, compute_client, subscription_id)),
            ("Azure Network Security Groups", partial(scan_network_security_groups, network_client, subscription_id)),
            ("Azure SQL Database Encryption", partial(scan_sql_database_encryption, sql_client, subscription_id)),
            ("Azure Key Vault Access Policies", partial(scan_key_vault_access_policies, keyvault_client, subscription_id)),
            ("Azure Web App HTTPS Configuration", partial(scan_web_app_https_only, web_client, subscription_id)),
        ])
        
    except Exception as e:
        logging.error(f"Failed to initialize Azure clients: {e}")
        functions_to_run.append(
            ("Azure Scanner Initialization", lambda: [handle_azure_exception("Azure Services", "initialize clients", e)])
        )
    
    logging.info(f"Initialized {len(functions_to_run)} Azure scan functions")
    return functions_to_run