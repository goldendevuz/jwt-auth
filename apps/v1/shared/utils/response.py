from rest_framework.response import Response

def success_response(message: str = None, data: dict = None,status_code: int = 200):
    return Response({
        "status": True,
        "message": message,
        'data': data
    }, status=status_code)
