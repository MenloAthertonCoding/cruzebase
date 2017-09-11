from django.conf.urls import url

from authtoken import views

urlpatterns = [
    url(r'^$', views.ObtainAuthToken.as_view(), name='obtain-auth-token')
]