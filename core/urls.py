from django.conf.urls.static import static
from django.contrib import admin
from django.urls import path, include

from core.settings import MEDIA_URL, MEDIA_ROOT, STATIC_URL, STATIC_ROOT
from apps.v1.shared.views import test, api_root

urlpatterns = [
    path('admin/', admin.site.urls),
    path("__debug__/", include("debug_toolbar.urls")),
    # path('user/', api_users, name='api-users'),
    path('api/v1/user/', include('apps.v1.users.urls')),
    path('api/v1/post/', include('apps.v1.post.urls')),
    path('api/v1/api-auth/', include('rest_framework.urls')),  # Important for login/logout
    path('', api_root, name='api-root'),
    path('api/v1/test-login/', test, name='test'),
]

urlpatterns += static(MEDIA_URL, document_root=MEDIA_ROOT)
urlpatterns += static(STATIC_URL, document_root=STATIC_ROOT)