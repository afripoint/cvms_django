from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, re_path, include
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from rest_framework import permissions, routers


schema_view = get_schema_view(
    openapi.Info(
        title="Custom Verification Management System",
        default_version="v1",
        description="",
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

urlpatterns = [
     re_path(
        r"^swagger(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    path(
        "api/documentation/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    re_path(
        r"^redoc/$", schema_view.with_ui("redoc", cache_timeout=0), name="schema-redoc"
    ),
    path("admin/", admin.site.urls),
    path("auth/", include("accounts.urls")),
    path("logs/", include("logs.urls")),
    path("roles/", include("roles.urls")),
    path("all_foriegn_objects/", include("departments.urls")),
    path("verification_mobile/", include("verifications.urls")),
    path("data_uploads/", include("data_uploads.urls")),
    path("security_logs/", include("security_logs.urls")),
    path("permissions/", include("permissions.urls")),
    path("auth_mobile/", include("accounts_mobile.urls")),
    path("products/", include("products.urls")),
    path("admin-resolution/", include("admin_rosolutions.urls")),
    path("analytics/", include("admin_analytics.urls")),
    path("tracker/", include("tracker.urls")),
]


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
