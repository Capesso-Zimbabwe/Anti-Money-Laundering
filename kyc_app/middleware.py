import logging
import traceback
from django.db import connection

logger = logging.getLogger(__name__)

class DatabaseErrorLoggingMiddleware:
    """
    Middleware to log database errors with detailed information
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request
        response = self.get_response(request)
        
        # After view is called, check for database errors
        if hasattr(connection, 'queries'):
            for query in connection.queries:
                if 'error' in query.get('sql', '').lower():
                    # Log the error query
                    logger.error(f"Database Query Error: {query.get('sql')}")
                    logger.error(f"Error time: {query.get('time')}")
                    
                    # Log the request parameters
                    logger.error(f"Request Method: {request.method}")
                    logger.error(f"Request Path: {request.path}")
                    if request.method == 'POST':
                        # Log POST parameters, omitting sensitive fields
                        safe_post = {k: v for k, v in request.POST.items() 
                                    if not any(sensitive in k.lower() for sensitive in 
                                              ['password', 'token', 'key', 'secret'])}
                        logger.error(f"POST Parameters: {safe_post}")
        
        return response
        
    def process_exception(self, request, exception):
        """
        Process exceptions from views
        """
        # Log the exception details
        logger.error(f"Exception in request {request.path}: {exception}")
        logger.error(traceback.format_exc())
        
        # Check for database-related exceptions
        if 'DatabaseError' in exception.__class__.__name__:
            logger.error("Database Error Details:")
            if hasattr(exception, 'params'):
                logger.error(f"Parameters: {exception.params}")
            
            # Log field length errors specifically
            if 'value too long for type character varying' in str(exception):
                logger.error("Character Field Length Error Detected")
                if request.method == 'POST':
                    # Log lengths of all fields to help identify the issue
                    field_lengths = {k: len(v) for k, v in request.POST.items() if len(v) > 30}
                    logger.error(f"Field lengths > 30 chars: {field_lengths}")
        
        return None 