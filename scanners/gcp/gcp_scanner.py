import google.cloud.storage
from google.cloud import resourcemanager_v3
from google.oauth2 import service_account
from googleapiclient import discovery
from functools import partial
import json
import os
import logging

def scan_gcs_public_buckets(gcp_client):
    """
    Scans for GCS buckets that are publicly accessible.
    """
    logging.debug("Starting scan: GCS Public Buckets")
    results = []
    try:
        buckets = list(gcp_client.list_buckets())
        logging.debug(f"Found {len(buckets)} GCS buckets to analyze.")
        for bucket in buckets:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            is_public = False
            for binding in policy.bindings:
                if binding['role'] == 'roles/storage.objectViewer' and 'allUsers' in binding['members']:
                    is_public = True
                    break
            
            logging.debug(f"  -> Bucket '{bucket.name}' is public: {is_public}.")
            if is_public:
                results.append({
                    "service": "GCS", 
                    "resource": bucket.name, 
                    "status": "CRITICAL", 
                    "issue": "Bucket is publicly accessible to allUsers.",
                    "remediation": "Remove 'allUsers' from the 'Storage Object Viewer' role in the bucket's IAM policy."
                })
            else:
                 results.append({
                    "service": "GCS", 
                    "resource": bucket.name, 
                    "status": "OK", 
                    "issue": "Bucket is not public."
                })
    except Exception as e:
        results.append({"service": "GCS", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan GCS buckets: {str(e)}"})
    logging.debug(f"Finished scan: GCS Public Buckets. Found {len(results)} results.")
    return results

def scan_gcp_iam_overly_permissive_roles(credentials):
    """
    Scans for overly permissive roles (owner, editor) on the project level.
    """
    logging.debug("Starting scan: GCP Project IAM Overly Permissive Roles")
    results = []
    try:
        key_data = json.loads(credentials.get("gcp_service_account_json"))
        project_id = key_data.get('project_id')
        if not project_id:
            logging.error("Could not determine project_id from credentials for IAM scan.")
            return [{"service": "IAM", "resource": "Project", "status": "ERROR", "issue": "Could not determine project_id from credentials."}]

        logging.debug(f"Scanning IAM policy for project '{project_id}'.")
        iam_client = resourcemanager_v3.ProjectsClient()
        policy = iam_client.get_iam_policy(resource=f"projects/{project_id}")

        overly_permissive_roles = {'roles/owner', 'roles/editor'}
        found_critical = False
        for binding in policy.bindings:
            role = binding.role
            if role in overly_permissive_roles:
                found_critical = True
                for member in binding.members:
                    logging.debug(f"  -> Found principal '{member}' with permissive role '{role}'.")
                    results.append({
                        "service": "IAM",
                        "resource": f"Project: {project_id}",
                        "status": "CRITICAL",
                        "issue": f"Principal '{member}' has an overly permissive role: '{role}'.",
                        "remediation": f"Review the principal's permissions and assign a more restrictive, predefined role or create a custom role following the principle of least privilege."
                    })
        
        if not found_critical:
             logging.debug("  -> No principals with Owner/Editor roles found.")
             results.append({
                "service": "IAM", 
                "resource": f"Project: {project_id}", 
                "status": "OK", 
                "issue": "No principals with Owner/Editor roles found at the project level."
            })

    except Exception as e:
        results.append({"service": "IAM", "resource": "Project", "status": "ERROR", "issue": f"Could not scan project IAM policies: {str(e)}"})
    logging.debug(f"Finished scan: GCP Project IAM Overly Permissive Roles. Found {len(results)} results.")
    return results

def scan_gce_firewall_rules_open_to_world(compute_service, project_id):
    """
    Scans GCE firewall rules for ports open to the internet (0.0.0.0/0).
    """
    logging.debug(f"Starting scan: GCE Firewall Rules Open to World for project '{project_id}'")
    results = []
    try:
        request = compute_service.firewalls().list(project=project_id)
        response = request.execute()
        
        all_rules = response.get('items', [])
        logging.debug(f"Found {len(all_rules)} firewall rules to analyze.")
        found_critical = False
        for rule in all_rules:
            if rule.get('disabled'):
                continue

            if rule.get('direction') == 'INGRESS' and '0.0.0.0/0' in rule.get('sourceRanges', []):
                ports = []
                for allowed in rule.get('allowed', []):
                    protocol = allowed.get('IPProtocol', 'all').upper()
                    if 'ports' in allowed:
                        ports.extend([f"{p} ({protocol})" for p in allowed['ports']])
                    else:
                        ports.append(f"all ({protocol})")
                
                if ports:
                    found_critical = True
                    logging.debug(f"  -> Found firewall rule '{rule['name']}' open to the world.")
                    results.append({
                        "service": "GCE Firewall",
                        "resource": rule['name'],
                        "status": "CRITICAL",
                        "issue": f"Firewall rule allows inbound traffic from 0.0.0.0/0 on ports: {', '.join(ports)}.",
                        "remediation": "Restrict the source ranges to only trusted IP addresses. Avoid using 0.0.0.0/0."
                    })

        if not found_critical:
            logging.debug("  -> No ingress firewall rules open to 0.0.0.0/0 found.")
            results.append({
                "service": "GCE Firewall",
                "resource": f"Project: {project_id}",
                "status": "OK",
                "issue": "No active ingress firewall rules found allowing traffic from 0.0.0.0/0."
            })

    except Exception as e:
        results.append({"service": "GCE Firewall", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan GCE firewall rules: {str(e)}"})
    logging.debug(f"Finished scan: GCE Firewall Rules Open to World. Found {len(results)} results.")
    return results

def scan_cloud_sql_publicly_accessible(sql_service, project_id):
    """
    Scans Cloud SQL instances to see if they are publicly accessible.
    """
    logging.debug(f"Starting scan: Cloud SQL Publicly Accessible for project '{project_id}'")
    results = []
    try:
        request = sql_service.instances().list(project=project_id)
        response = request.execute()
        
        instances = response.get('items', [])
        logging.debug(f"Found {len(instances)} Cloud SQL instances to analyze.")
        if not instances:
            results.append({"service": "Cloud SQL", "resource": f"Project: {project_id}", "status": "OK", "issue": "No Cloud SQL instances found."})
        else:
            for instance in instances:
                is_public = False
                ip_config = instance.get('settings', {}).get('ipConfiguration', {})
                if ip_config.get('ipv4Enabled'):
                    for network in ip_config.get('authorizedNetworks', []):
                        if network.get('value') == "0.0.0.0/0":
                            is_public = True
                            break
                
                logging.debug(f"  -> Cloud SQL instance '{instance['name']}' is public: {is_public}.")
                if is_public:
                    results.append({"service": "Cloud SQL", "resource": instance['name'], "status": "CRITICAL", "issue": "Database instance has a public IP and is open to the world.", "remediation": "Remove '0.0.0.0/0' from authorized networks and use the Cloud SQL Auth Proxy."})
                else:
                    results.append({"service": "Cloud SQL", "resource": instance['name'], "status": "OK", "issue": "Database instance is not publicly accessible."})

    except Exception as e:
        results.append({"service": "Cloud SQL", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan Cloud SQL instances: {str(e)}"})
    logging.debug(f"Finished scan: Cloud SQL Publicly Accessible. Found {len(results)} results.")
    return results

def scan_gcp_logging_sinks(logging_service, project_id):
    """
    Checks if a log sink is configured to capture logs for the project.
    """
    logging.debug(f"Starting scan: Cloud Logging Sinks for project '{project_id}'")
    results = []
    try:
        parent = f"projects/{project_id}"
        request = logging_service.projects().sinks().list(parent=parent)
        response = request.execute()

        sinks = response.get('sinks', [])
        logging.debug(f"Found {len(sinks)} log sinks to analyze.")
        if not sinks:
            results.append({"service": "Cloud Logging", "resource": f"Project: {project_id}", "status": "CRITICAL", "issue": "No log sinks are configured for this project.", "remediation": "Create a log sink to export audit logs for retention and analysis."})
        else:
            has_comprehensive_sink = any(not sink.get('filter') for sink in sinks)
            
            if has_comprehensive_sink:
                logging.debug("  -> Found a comprehensive log sink.")
                results.append({"service": "Cloud Logging", "resource": f"Project: {project_id}", "status": "OK", "issue": "A comprehensive log sink is configured."})
            else:
                logging.debug("  -> No comprehensive (empty filter) log sink found.")
                results.append({"service": "Cloud Logging", "resource": f"Project: {project_id}", "status": "WARNING", "issue": "Log sinks exist, but none capture all logs (i.e., no sink with an empty filter).", "remediation": "Ensure at least one sink has an empty filter to capture all project audit logs."})

    except Exception as e:
        results.append({"service": "Cloud Logging", "resource": "N/A", "status": "ERROR", "issue": f"Could not scan Cloud Logging sinks: {str(e)}"})
    logging.debug(f"Finished scan: Cloud Logging Sinks. Found {len(results)} results.")
    return results

def get_all_scan_functions(credentials, regions=None):
    """
    Prepares and returns a list of all GCP scan functions.
    """
    try:
        logging.debug("Initializing GCP clients for scanner.")
        gcp_json_key_str = credentials.get("gcp_service_account_json")
        key_data = json.loads(gcp_json_key_str)
        project_id = key_data.get('project_id')
        
        
        gcp_credentials = service_account.Credentials.from_service_account_info(key_data)
        
        gcs_client = google.cloud.storage.Client(credentials=gcp_credentials, project=project_id)
        sql_service = discovery.build('sqladmin', 'v1beta4', credentials=gcp_credentials, cache_discovery=False)
        compute_service = discovery.build('compute', 'v1', credentials=gcp_credentials, cache_discovery=False)
        logging_service = discovery.build('logging', 'v2', credentials=gcp_credentials, cache_discovery=False)
        
        # Additional GCP services for comprehensive scanning
        container_service = discovery.build('container', 'v1', credentials=gcp_credentials, cache_discovery=False)
        dns_service = discovery.build('dns', 'v1', credentials=gcp_credentials, cache_discovery=False)
        iam_service = discovery.build('iam', 'v1', credentials=gcp_credentials, cache_discovery=False)
        cloudkms_service = discovery.build('cloudkms', 'v1', credentials=gcp_credentials, cache_discovery=False)
        bigquery_service = discovery.build('bigquery', 'v2', credentials=gcp_credentials, cache_discovery=False)
        pubsub_service = discovery.build('pubsub', 'v1', credentials=gcp_credentials, cache_discovery=False)
        dataflow_service = discovery.build('dataflow', 'v1b3', credentials=gcp_credentials, cache_discovery=False)
        functions_service = discovery.build('cloudfunctions', 'v1', credentials=gcp_credentials, cache_discovery=False)
        run_service = discovery.build('run', 'v1', credentials=gcp_credentials, cache_discovery=False)
        monitoring_service = discovery.build('monitoring', 'v1', credentials=gcp_credentials, cache_discovery=False)
        secretmanager_service = discovery.build('secretmanager', 'v1', credentials=gcp_credentials, cache_discovery=False)
        redis_service = discovery.build('redis', 'v1', credentials=gcp_credentials, cache_discovery=False)
        filestore_service = discovery.build('file', 'v1', credentials=gcp_credentials, cache_discovery=False)
        dataproc_service = discovery.build('dataproc', 'v1', credentials=gcp_credentials, cache_discovery=False)
        spanner_service = discovery.build('spanner', 'v1', credentials=gcp_credentials, cache_discovery=False)
        bigtable_admin_service = discovery.build('bigtableadmin', 'v2', credentials=gcp_credentials, cache_discovery=False)
        deployment_manager_service = discovery.build('deploymentmanager', 'v2', credentials=gcp_credentials, cache_discovery=False)
        source_service = discovery.build('sourcerepo', 'v1', credentials=gcp_credentials, cache_discovery=False)
        build_service = discovery.build('cloudbuild', 'v1', credentials=gcp_credentials, cache_discovery=False)
        appengine_service = discovery.build('appengine', 'v1', credentials=gcp_credentials, cache_discovery=False)
        composer_service = discovery.build('composer', 'v1', credentials=gcp_credentials, cache_discovery=False)
        logging.debug("GCP clients initialized successfully.")

        functions_to_run = [
            # Only include functions that are actually defined
            ("GCS Public Buckets", partial(scan_gcs_public_buckets, gcs_client)),
            ("Project IAM Overly Permissive Roles", partial(scan_gcp_iam_overly_permissive_roles, credentials)),
            ("GCE Firewall Rules Open to World", partial(scan_gce_firewall_rules_open_to_world, compute_service, project_id)),
            ("Cloud SQL Publicly Accessible", partial(scan_cloud_sql_publicly_accessible, sql_service, project_id)),
            ("Cloud Logging Sinks", partial(scan_gcp_logging_sinks, logging_service, project_id)),
        ]
        
        return functions_to_run

    except Exception as e:
        logging.exception("Failed to initialize GCP scanner.")
        error_message = str(e)
        def report_init_error(msg=error_message):
            return [{"service": "GCP Scanner", "resource": "Initialization", "status": "ERROR", "issue": f"Could not initialize GCP clients. Check key or API permissions. Error: {msg}"}]
        return [("GCP Initialization", report_init_error)]
