from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from config import API_V1_URL
from core.settings import MEDIA_URL, MEDIA_ROOT, STATIC_URL, STATIC_ROOT

urlpatterns = [
    path('admin/', admin.site.urls),
    path("__debug__/", include("debug_toolbar.urls")),
    path(API_V1_URL+'user/', include('apps.v1.users.urls')),
    path(API_V1_URL+'api-auth/', include('rest_framework.urls')),  # Important for login/logout
    # path('restwind/', include('restwind.urls')),    # Restwind UI
]

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)
urlpatterns += static(STATIC_URL, document_root=STATIC_ROOT)