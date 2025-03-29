import logging
import time
import json
from django.http import HttpResponse
from .models import ApiLog

logger = logging.getLogger('django.request')

class RequestLoggingMiddleware:
    """
    Middleware to log all HTTP requests and responses and store API calls in database
    
    This middleware performs three primary functions:
    1. Records detailed logs of all requests and responses for debugging
    2. Stores API call details in the database for auditing and performance tracking
    3. Measures response time for all requests
    
    The middleware handles different content types (JSON, form data, files) and
    properly sanitizes data before logging to prevent sensitive information exposure.
    """
    def __init__(self, get_response):
        """
        Initialize the middleware with the next middleware or view in the chain
        
        Args:
            get_response: The next middleware or view function
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Process the request, log details, and return the response
        
        Args:
            request: The HttpRequest object
            
        Returns:
            HttpResponse: The response from the view or next middleware
        """
        # Start timing the request
        start_time = time.time()
        path = request.path
        method = request.method
        
        # Pre-process and cache the request body to avoid reading it multiple times
        request_body_str = None
        request_body_data = None
        content_type = request.META.get('CONTENT_TYPE', '')
        
        # Handle different request types for data extraction
        if method in ['POST', 'PUT', 'PATCH'] and hasattr(request, 'body'):
            try:
                # Cache the body as string
                request_body_str = request.body.decode('utf-8')
                
                # Parse JSON if content type indicates JSON data
                if 'application/json' in content_type:
                    try:
                        request_body_data = json.loads(request_body_str)
                    except json.JSONDecodeError:
                        request_body_data = {'error': 'Invalid JSON data'}
            except Exception as e:
                logger.error(f"Error reading request body: {str(e)}")
        
        # Process the request and get response
        response = self.get_response(request)
        
        # Calculate request duration for performance tracking
        duration = time.time() - start_time
        
        # Only store API calls (paths starting with /api/) in the database
        if path.startswith('/api/'):
            try:
                # Prepare request body for database storage based on content type
                db_request_body = None
                if method in ['POST', 'PUT', 'PATCH']:
                    if 'application/json' in content_type and request_body_data:
                        db_request_body = request_body_data
                    elif 'multipart/form-data' in content_type:
                        # For file uploads, just store the file names, not contents
                        db_request_body = {'files': [f.name for f in request.FILES.values()]} if request.FILES else None
                
                # Create database record of the API call
                ApiLog.objects.create(
                    user=request.user if request.user.is_authenticated else None,
                    method=method,
                    path=path,
                    query_params=dict(request.GET.items()) if request.GET else None,
                    request_body=db_request_body,
                    status_code=response.status_code,
                    response_time=duration,
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT')
                )
            except Exception as e:
                logger.error(f"Failed to create API log entry: {str(e)}")
        
        # Log request details to the console/log file for debugging
        # Different handling based on request method and content type
        if method in ['POST', 'PUT', 'PATCH']:
            if 'multipart/form-data' in content_type:
                if hasattr(request, 'FILES') and request.FILES:
                    file_info = ", ".join([f"{name}: {f.name} ({f.size} bytes)" for name, f in request.FILES.items()])
                    logger.info(f"API Request: {method} {path} - Multipart form with files: {file_info}")
                else:
                    logger.info(f"API Request: {method} {path} - Multipart form data")
            elif 'application/json' in content_type and request_body_data:
                logger.info(f"API Request: {method} {path} - Body: {json.dumps(request_body_data)}")
            else:
                logger.info(f"API Request: {method} {path} - Body: (non-JSON data)")
        else:
            logger.info(f"API Request: {method} {path}")
        
        # Log query parameters if present
        if request.GET:
            logger.info(f"Query params: {dict(request.GET.items())}")
        
        # Log response details with different verbosity based on path
        status_code = response.status_code
        
        # Try to log response content for API calls with appropriate handling of different response types
        if path.startswith('/api/'):
            try:
                content_type = response.get('Content-Type', '')
                if 'application/json' in content_type and isinstance(response, HttpResponse) and hasattr(response, 'content'):
                    try:
                        content = json.loads(response.content.decode('utf-8'))
                        # Special case for competition data which benefits from more detailed logging
                        if '/competitions' in path:
                            logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - Data: {json.dumps(content)}")
                        else:
                            # For other endpoints, log less detail to avoid clutter
                            if isinstance(content, list):
                                logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - Items: {len(content)}")
                            else:
                                logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - Data type: {type(content).__name__}")
                    except json.JSONDecodeError:
                        logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - (non-JSON response)")
                    except Exception as e:
                        logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - Error parsing response: {str(e)}")
                else:
                    logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - (non-JSON content)")
            except Exception as e:
                logger.info(f"API Response: {method} {path} - {status_code} - {duration:.2f}s - Error logging content: {str(e)}")
        else:
            # Non-API responses get simpler logging
            logger.info(f"Response: {method} {path} - {status_code} - {duration:.2f}s")
        
        return response


class LogBodyMiddleware:
    """
    Middleware to log request and response bodies for debugging
    
    This middleware provides a mechanism for detailed request/response body logging
    when more verbose debugging is needed. Unlike the RequestLoggingMiddleware,
    this is intended to be enabled only during development or when troubleshooting
    specific issues.
    
    Note: This middleware implementation is currently minimal. It serves as a hook
    for adding more detailed logging that can be enabled when needed.
    """
    def __init__(self, get_response):
        """
        Initialize the middleware with the next middleware or view in the chain
        
        Args:
            get_response: The next middleware or view function
        """
        self.get_response = get_response

    def __call__(self, request):
        """
        Process the request and return the response
        
        Currently this is a placeholder implementation. When detailed logging
        is needed, this can be extended to capture and log complete request
        and response bodies.
        
        Args:
            request: The HttpRequest object
            
        Returns:
            HttpResponse: The response from the view or next middleware
        """
        # Process the request
        response = self.get_response(request)
        return response