from django.conf.urls import url

from authtoken import views

app_name = 'authtoken'

urlpatterns = [
    url(r'^$', views.ObtainAuthToken.as_view(), name='obtain-auth-token')
]