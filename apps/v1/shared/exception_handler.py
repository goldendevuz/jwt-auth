import logging
from rest_framework.views import exception_handler

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        response.data['success'] = False
        response.data['status_code'] = response.status_code
        logger.error(f"Response Data: {response.data}")  # Log the response structure for debugging

        # # Wrap with "success": False for non-2xx responses
        # if response.status_code < 200 or response.status_code >= 300:
        #     # Check if response is a dict (it should be)
        #     if isinstance(response.data, dict):
        #         # Check for 'detail' errors (e.g., for authentication)
        #         if 'detail' in response.data:
        #             response.data['detail'] = response.data['detail']
        #         # Check for non-field errors
        #         elif 'non_field_errors' in response.data:
        #             response.data['errors'] = response.data['non_field_errors']
        #         # Handle field-specific errors (e.g. "photo": ["No file was submitted."])
        #         # elif any(isinstance(v, list) for v in response.data.values()):
        #         #     response.data['errors'] = {key: value for key, value in response.data.items() if isinstance(value, list)}
        #         else:
        #             # For any other errors, wrap them generically
        #             response.data['errors'] = response.data

    return response
