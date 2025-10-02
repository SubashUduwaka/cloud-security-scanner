import importlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError

def get_scan_functions_for_provider(credentials, regions):
    """
    Acts as a factory to dynamically load and retrieve the scan functions
    for the specified cloud provider.
    """
    provider = credentials.get('provider')
    if not provider:
        raise ValueError("Provider not specified in credentials.")

    try:
        # Construct the module name dynamically, e.g., 'scanners.aws.aws_scanner'
        module_name = f"scanners.{provider}.{provider}_scanner"
        # ELEVATED THIS LOG MESSAGE
        logging.info(f"--- [CORE] Dynamically loading scanner module: {module_name} ---")
        # Dynamically import the module
        scanner_module = importlib.import_module(module_name)
        # Call the get_all_scan_functions from the loaded module
        scan_functions = scanner_module.get_all_scan_functions(credentials, regions)
        # DEBUG: Log the number of functions found
        logging.debug(f"Successfully loaded {len(scan_functions)} scan functions for provider '{provider}'.")
        return scan_functions
    except (ImportError, AttributeError) as e:
        # Use logging.exception to capture the full error traceback
        logging.exception(f"ERROR: Could not load scanner module for provider '{provider}'.")
        raise ImportError(f"No scanner found for provider: {provider}")


def run_parallel_scans_progress(credentials, regions=None):
    """
    A generator that runs scans in parallel for the given provider and yields
    progress updates and results as they complete.
    """
    # Get the specific list of scan functions for the selected provider
    scan_functions = get_scan_functions_for_provider(credentials, regions)

    max_workers = 15
    logging.debug(f"Initializing ThreadPoolExecutor with max_workers={max_workers}.")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_scan = {}
        for name, scan_func in scan_functions:
            logging.debug(f"Submitting scan '{name}' to the thread pool.")
            future = executor.submit(scan_func)
            future_to_scan[future] = name

        for future in as_completed(future_to_scan):
            scan_name = future_to_scan[future]
            try:
                logging.debug(f"Scan '{scan_name}' has completed.")
                # Get the actual results from the completed scan
                result = future.result()
                logging.debug(f"Result for '{scan_name}': {len(result)} findings.")
                # Yield a progress update to the frontend
                yield {"status": "progress", "message": f"Completed: {scan_name}"}
                # Yield the list of results to be collected
                yield result
            except Exception as e:
                logging.exception(f"ERROR in scan '{scan_name}'.")
                # Yield an error result that can be displayed
                yield [{"service": "Scanner", "resource": scan_name, "status": "ERROR", "issue": f"Scan function failed: {str(e)}"}]


def run_parallel_scans_blocking(credentials, regions=None):
    """
    Runs all scans in parallel for the given provider using a thread pool.
    Returns a single list of all results only when everything is complete.
    """
    all_results = []
    # Get the specific list of scan functions for the selected provider
    scan_functions = get_scan_functions_for_provider(credentials, regions)
    
    max_workers = 15
    logging.debug(f"Initializing ThreadPoolExecutor with max_workers={max_workers} for blocking scan.")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_scan = {executor.submit(scan_func): name for name, scan_func in scan_functions}

        for future in as_completed(future_to_scan):
            scan_name = future_to_scan[future]
            try:
                logging.debug(f"Blocking scan '{scan_name}' has completed.")
                result = future.result(timeout=300)
                all_results.extend(result)
            except TimeoutError: # You may need to import this from concurrent.futures
                logging.error(f"ERROR: Scan '{scan_name}' timed out after 300 seconds.")
                all_results.append({"service": "Scanner", "resource": scan_name, "status": "ERROR", "issue": "Scan timed out."})
            except Exception as e:
                logging.exception(f"ERROR in blocking scan '{scan_name}'.")
                all_results.append({"service": "Scanner", "resource": scan_name, "status": "ERROR", "issue": f"Scan function failed: {str(e)}"})

    return all_results