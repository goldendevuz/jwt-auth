from rest_framework.response import Response

def success_response(message: str, status_code: int = 200):
    return Response({
        "status": True,
        "message": message,
    }, status=status_code)
